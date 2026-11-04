const form = document.querySelector("#login-form");
const password = document.querySelector("#password");
const togglePassword = document.querySelector("#toggle-password");
const setupNote = document.querySelector("#setup-note");
const submitButton = form.querySelector('button[type="submit"]');

togglePassword.addEventListener("click", () => {
  const showPassword = password.type === "password";
  password.type = showPassword ? "text" : "password";
  togglePassword.textContent = showPassword ? "Hide" : "Show";
  togglePassword.setAttribute("aria-pressed", String(showPassword));
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  setupNote.classList.remove("error");
  setupNote.textContent = "Signing in…";
  submitButton.disabled = true;

  try {
    const response = await fetch("auth/login", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({
        username: form.elements.username.value,
        password: form.elements.password.value
      })
    });

    if (response.status === 401) {
      throw new Error("Username or password was not accepted.");
    }

    if (response.status === 403) {
      throw new Error("Your account does not have access to this report.");
    }

    if (!response.ok) {
      throw new Error("Could not sign in. Please try again later.");
    }

    password.value = "";
    window.location.assign("index.html");
  } catch (error) {
    setupNote.classList.add("error");
    setupNote.textContent = error instanceof TypeError
      ? "Could not reach the report service. Please try again."
      : error.message;
  } finally {
    submitButton.disabled = false;
  }
});
