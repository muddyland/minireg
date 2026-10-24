/**
 * One way to turn a failed call into text for the page.
 *
 * `api` throws ApiError with the server's `detail`; a network failure throws
 * a TypeError whose message ("Failed to fetch") is still better than nothing.
 * Views keep an `error` ref, render it in an `alert alert-error` with
 * role="alert", and set it from every awaited call that can fail, so a page
 * never sits on "Loading…" or swallows a failed button press.
 */
export function errorMessage(err, fallback = 'Something went wrong.') {
  if (!err) return fallback
  return err.detail || err.message || fallback
}
