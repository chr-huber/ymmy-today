/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./templates/**/*.html"],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        paper: '#F9F9F9',
        finnish: {
          50: '#EEF4FB',
          100: '#DCE9F8',
          200: '#B9D3F1',
          300: '#8FB6E7',
          400: '#5F91DA',
          500: '#3F74C5',
          600: '#2F5EA5',
          700: '#254A84',
          800: '#203F6D',
          900: '#1D365C'
        }
      },
      fontFamily: {
        sans: ['Noto Sans', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        serif: ['Georgia', 'serif']
      }
    }
  }
}
