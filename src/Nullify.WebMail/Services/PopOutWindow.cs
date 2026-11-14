// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.JSInterop;

namespace Nullify.WebMail.Services;

/// <summary>
/// What a pop-out window (a message, or one being written) loads for itself: it has its own
/// circuit, so none of the main window's state is there.
/// </summary>
public static class PopOutWindow
{
    /// <summary>Folders, signature, senders and branding, as the main window loads them. Each is optional.</summary>
    public static async Task LoadAsync(ApiService api, BrandingService branding, AppState state)
    {
        try { state.Folders = await api.GetFoldersAsync(); } catch { /* Archive and Move unavailable */ }
        try
        {
            foreach (var p in await api.GetPreferencesAsync())
            {
                if (p.Key == "compose.signature") state.Signature = p.Value ?? "";
                if (p.Key == "compose.font") state.ComposeFont = p.Value ?? "sans-serif";
            }
        }
        catch { /* defaults */ }
        try { state.Senders = await api.GetSendersAsync(); } catch { /* the sign-in address */ }
        try { state.BrandTitle = await branding.TitleAsync(); } catch { /* default title */ }
    }

    /// <summary>
    /// Once interactive: the browser's time zone, and Ctrl/Cmd+Enter to send (the window calls
    /// <c>OnSendShortcut</c> on <paramref name="window"/>). True when the time zone changed.
    /// </summary>
    public static async Task<bool> InitBrowserAsync<T>(IJSRuntime js, AppState state, DotNetObjectReference<T> window) where T : class
    {
        // Without these the window still works: no send shortcut, and times in the server's zone.
        await js.TryInvokeVoidAsync("nullifyApp.windowKeys", window);
        var tz = await js.TryInvokeAsync<string?>("nullifyApp.timeZone", null);
        if (string.IsNullOrEmpty(tz) || !TimeZoneInfo.TryFindSystemTimeZoneById(tz, out var zone)) return false;
        state.TimeZone = zone;
        return true;
    }
}
