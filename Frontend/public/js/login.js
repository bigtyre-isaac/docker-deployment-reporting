const form = document.querySelector("#login-form");
const password = document.querySelector("#password");
const togglePassword = document.querySelector("#toggle-password");
const setupNote = document.querySelector("#setup-note");

togglePassword.addEventListener("click", () => {
  const showPassword = password.type === "password";
  password.type = showPassword ? "text" : "password";
  togglePassword.textContent = showPassword ? "Hide" : "Show";
  togglePassword.setAttribute("aria-pressed", String(showPassword));
});

form.addEventListener("submit", (event) => {
  event.preventDefault();
  setupNote.classList.add("error");
  setupNote.textContent = "Sign-in is not connected yet. Your credentials were not sent.";
});
