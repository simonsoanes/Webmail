// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.JSInterop;

namespace Nullify.WebMail.Services;

/// <summary>
/// Calls into wwwroot/js/app.js for which a failure has a sensible stand-in: the circuit has gone,
/// the call timed out, or the page's script threw. Calls whose failure the caller must report go
/// through their own try/catch instead.
/// </summary>
public static class BrowserJs
{
    /// <summary>The failures a JS interop call can end in, as opposed to bugs on this side.</summary>
    public static bool IsInteropFailure(Exception ex) =>
        ex is JSException or JSDisconnectedException or TaskCanceledException or ObjectDisposedException;

    /// <summary>The browser's confirm dialog. False when it can't be shown, so nothing runs unconfirmed.</summary>
    public static Task<bool> ConfirmAsync(this IJSRuntime js, string message) =>
        js.TryInvokeAsync("nullifyApp.confirm", false, message);

    /// <summary>Calls <paramref name="identifier"/>, or gives <paramref name="fallback"/> when the call fails.</summary>
    public static async Task<T> TryInvokeAsync<T>(this IJSRuntime js, string identifier, T fallback, params object?[] args)
    {
        try { return await js.InvokeAsync<T>(identifier, args); }
        catch (Exception ex) when (IsInteropFailure(ex)) { return fallback; }
    }

    /// <summary>Calls <paramref name="identifier"/>; false when the call failed.</summary>
    public static async Task<bool> TryInvokeVoidAsync(this IJSRuntime js, string identifier, params object?[] args)
    {
        try { await js.InvokeVoidAsync(identifier, args); return true; }
        catch (Exception ex) when (IsInteropFailure(ex)) { return false; }
    }
}
