export const isMac = (() => {
  if (typeof navigator === 'undefined') return false
  const ua = (navigator as Navigator & { userAgentData?: { platform?: string } }).userAgentData
  const plat = ua?.platform ?? navigator.platform ?? ''
  return plat.toUpperCase().indexOf('MAC') >= 0
})()

export function K(key: string) {
  if (key === 'Esc') return 'Esc'
  const [letter, mod] = key.split('+')
  const cmd = isMac ? '⌘' : 'Ctrl+'
  const shift = isMac ? '⇧' : 'Shift+'
  const prefix = mod === 'shift' ? `${cmd}${shift}` : cmd
  return `${prefix}${letter}`
}
