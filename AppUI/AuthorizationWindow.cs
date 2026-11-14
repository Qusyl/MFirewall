using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using MFirewallApp.Dto;

namespace MFirewallAppUI
{
    public partial class AuthorizationWindow : Window
    {
        private bool _isAdmin = false;
        private bool _isAuthorized = false;

        public bool IsAdmin => _isAdmin;
        public bool IsAuthorized => _isAuthorized;

        private static readonly HttpClient httpClient = new()
        {
            BaseAddress = new Uri("http://localhost:5118")
        };

        public AuthorizationWindow()
        {
            InitializeComponent();

            // Enter в поле пароля = нажать «Войти»
            LoginPassword.KeyDown += OnLoginKeyDown;
            RegisterPasswordConfirm.KeyDown += OnRegisterKeyDown;
        }

        // ===================== LOGIN =====================
        private async void OnLoginClick(object? sender, RoutedEventArgs args)
        {
            var email = LoginEmail.Text?.Trim() ?? "";
            var password = LoginPassword.Text ?? "";

            if (!ValidateLogin(email, password)) return;

            SetLoginBusy(true);
            HideLoginMessages();

            try
            {
                var loginDto = new UserLoginDto(email, password);

                using var response = await httpClient.PostAsJsonAsync("/login", loginDto);

                if (!response.IsSuccessStatusCode)
                {
                    ShowError(LoginError, response.StatusCode switch
                    {
                        System.Net.HttpStatusCode.Unauthorized => "Неверный email или пароль",
                        System.Net.HttpStatusCode.BadRequest   => "Некорректные данные",
                        _                                      => $"Ошибка сервера: {(int)response.StatusCode}"
                    });
                    return;
                }

                var dto = await response.Content.ReadFromJsonAsync<AuthResponseDto>();
                if (dto is null)
                {
                    ShowError(LoginError, "Пустой ответ сервера");
                    return;
                }

                _isAdmin = dto.Roles.Contains("Admin");
                _isAuthorized = true;

                ShowSuccess(LoginSuccess,
                    _isAdmin
                        ? "Успешно! Вы вошли как администратор. Окно закроется…"
                        : "Успешно! Вы вошли как пользователь. Окно закроется…");

                await Task.Delay(600);   // дать пользователю прочитать сообщение
                Close();
            }
            catch (HttpRequestException)
            {
                ShowError(LoginError, "Сервер недоступен. Проверьте подключение.");
            }
            catch (TaskCanceledException)
            {
                ShowError(LoginError, "Превышено время ожидания ответа сервера.");
            }
            catch (Exception ex)
            {
                ShowError(LoginError, $"Ошибка: {ex.Message}");
            }
            finally
            {
                SetLoginBusy(false);
            }
        }

        // ===================== REGISTER =====================
        private async void OnRegisterClick(object? sender, RoutedEventArgs args)
        {
            var email = RegisterEmail.Text?.Trim() ?? "";
            var password = RegisterPassword.Text ?? "";
            var confirm = RegisterPasswordConfirm.Text ?? "";

            if (!ValidateRegister(email, password, confirm)) return;

            SetRegisterBusy(true);
            HideRegisterMessages();

            try
            {
                var register = new UserRegistrationDto(email, password);

                using var response = await httpClient.PostAsJsonAsync("/Register", register);

                if (!response.IsSuccessStatusCode)
                {
                    ShowError(RegisterError, response.StatusCode switch
                    {
                        System.Net.HttpStatusCode.BadRequest  => "Некорректные данные (email занят?)",
                        System.Net.HttpStatusCode.Conflict    => "Такой email уже зарегистрирован",
                        _                                     => $"Ошибка сервера: {(int)response.StatusCode}"
                    });
                    return;
                }

                var dto = await response.Content.ReadFromJsonAsync<AuthResponseDto>();
                if (dto is null)
                {
                    ShowError(RegisterError, "Пустой ответ сервера");
                    return;
                }

                _isAdmin = dto.Roles.Contains("Admin");
                _isAuthorized = true;

                ShowSuccess(RegisterSuccess, "Аккаунт создан! Окно закроется…");

                await Task.Delay(600);
                Close();
            }
            catch (HttpRequestException)
            {
                ShowError(RegisterError, "Сервер недоступен. Проверьте подключение.");
            }
            catch (TaskCanceledException)
            {
                ShowError(RegisterError, "Превышено время ожидания ответа сервера.");
            }
            catch (Exception ex)
            {
                ShowError(RegisterError, $"Ошибка: {ex.Message}");
            }
            finally
            {
                SetRegisterBusy(false);
            }
        }

        // ===================== HELPERS =====================
        private bool ValidateLogin(string email, string password)
        {
            if (string.IsNullOrWhiteSpace(email) || !email.Contains('@'))
            {
                ShowError(LoginError, "Введите корректный email");
                return false;
            }
            if (string.IsNullOrEmpty(password))
            {
                ShowError(LoginError, "Введите пароль");
                return false;
            }
            return true;
        }

        private bool ValidateRegister(string email, string password, string confirm)
        {
            if (string.IsNullOrWhiteSpace(email) || !email.Contains('@'))
            {
                ShowError(RegisterError, "Введите корректный email");
                return false;
            }
            if (password.Length < 6)
            {
                ShowError(RegisterError, "Пароль должен быть не короче 6 символов");
                return false;
            }
            if (password != confirm)
            {
                ShowError(RegisterError, "Пароли не совпадают");
                return false;
            }
            return true;
        }

        private void SetLoginBusy(bool busy)
        {
            LoginProgress.IsVisible = busy;
            LoginButton.IsEnabled = !busy;
            LoginButton.Content = busy ? "Проверяем…" : "Войти";
        }

        private void SetRegisterBusy(bool busy)
        {
            RegisterProgress.IsVisible = busy;
            RegisterButton.IsEnabled = !busy;
            RegisterButton.Content = busy ? "Создаём…" : "Создать аккаунт";
        }

        private void HideLoginMessages()
        {
            LoginError.IsVisible = false;
            LoginSuccess.IsVisible = false;
        }

        private void HideRegisterMessages()
        {
            RegisterError.IsVisible = false;
            RegisterSuccess.IsVisible = false;
        }

        private static void ShowError(TextBlock target, string message)
        {
            target.Text = message;
            target.IsVisible = true;
        }

        private static void ShowSuccess(TextBlock target, string message)
        {
            target.Text = message;
            target.IsVisible = true;
        }

        private void OnLoginKeyDown(object? sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) OnLoginClick(null, new RoutedEventArgs());
        }

        private void OnRegisterKeyDown(object? sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) OnRegisterClick(null, new RoutedEventArgs());
        }
    }
}