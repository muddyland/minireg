/**
 * The URL, normalised, if it is http or https; otherwise null.
 *
 * Several links on these pages carry upstream data: an npm package's
 * homepage, OSV advisory references, Trivy's advisory URLs, image labels --
 * i.e. text chosen by whoever published the package, advisory or image. Vue
 * does not sanitise a bound :href, so `javascript:fetch(...)` there runs in
 * this origin, with the viewer's session, when clicked. Every such link goes
 * through this check; callers show the text unlinked (or drop the link) when
 * it returns null.
 *
 * Parsed with URL rather than matched with a regex because browsers strip
 * leading whitespace and control characters and ignore case in the scheme
 * (`  JaVaScRiPt:` still runs); URL applies the same rules.
 */
export function safeHttpUrl(value) {
  if (typeof value !== 'string' || !value.trim()) return null
  let url
  try {
    url = new URL(value.trim())
  } catch {
    return null
  }
  return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : null
}
