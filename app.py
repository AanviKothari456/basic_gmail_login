// File: script.js
const BASE_URL = "https://basic-gmail-login.onrender.com";

async function login() {
  window.location.href = `${BASE_URL}/login`;
}

async function loadEmail() {
  try {
    const res = await fetch(`${BASE_URL}/latest_email`, { credentials: "include" });
    if (res.status === 401) {
      document.getElementById("content").style.display = "none";
      return;
    }
    document.getElementById("loginBtn").style.display = "none";

    const data = await res.json();
    document.getElementById("subject").innerText = data.subject || "(No subject)";
    document.getElementById("body").innerText = data.body || "(No body)";
    document.getElementById("emailAudio").src = `data:audio/mpeg;base64,${data.audio_base64}`;
    document.getElementById("content").style.display = "block";
  } catch (err) {
    console.error("Error loading email:", err);
    alert("Something went wrong while fetching your email.");
  }
}

let recognition;
if ("webkitSpeechRecognition" in window || "SpeechRecognition" in window) {
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  recognition = new SpeechRecognition();
  recognition.lang = "en-US";
  recognition.continuous = false;

  recognition.onresult = (event) => {
    const transcript = event.results[0][0].transcript;
    document.getElementById("transcript").innerText = "You said: " + transcript;
    document.getElementById("transcript").dataset.reply = transcript;
  };

  recognition.onerror = (event) => {
    alert("Mic error: " + event.error);
  };
} else {
  alert("Your browser does not support voice input (try Chrome).");
}

function startRecording() {
  document.getElementById("transcript").innerText = "";
  document.getElementById("transcript").dataset.reply = "";
  if (recognition) recognition.start();
}

function stopRecording() {
  if (recognition) recognition.stop();
}

async function sendReply() {
  // Grab whatever you just spoke:
  const userInstruction = document.getElementById("transcript").dataset.reply;
  if (!userInstruction) {
    return alert("Please speak a reply instruction first.");
  }

  // Send it to /send_reply to get back the AI‐formatted email text
  const res = await fetch(`${BASE_URL}/send_reply`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ reply: userInstruction })
  });

  if (!res.ok) {
    const err = await res.json();
    return alert("Error: " + (err.error || JSON.stringify(err)));
  }

  const json = await res.json();
  // Display the AI‐generated reply in a <pre id="aiReply"></pre>
  document.getElementById("aiReply").innerText = json.formatted_reply;
}

// On page load, hide or show appropriately
window.onload = () => {
  const urlParams = new URLSearchParams(window.location.search);
  const isLoggedIn = urlParams.get("logged_in") === "true";
  if (isLoggedIn) {
    document.getElementById("loginBtn").style.display = "none";
    loadEmail();
  }
};
