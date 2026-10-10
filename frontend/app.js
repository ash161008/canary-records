/* Canary Records frontend.
 *
 * This file displays backend results. It never decides whether an action was
 * allowed, quarantined, held or blocked: those decisions come from the
 * backend gateway and are only rendered here. Any data that originates from a
 * file, a log or a model response is written with textContent, never
 * innerHTML.
 */

"use strict";

const SCREENS = ["problem", "seed", "run", "audit", "scoreboard"];

/* ---------- screen navigation ---------- */

function showScreen(name) {
  if (!SCREENS.includes(name)) {
    return;
  }

  document.querySelectorAll(".screen").forEach((section) => {
    section.classList.toggle("is-active", section.id === `screen-${name}`);
  });

  document.querySelectorAll(".navbtn").forEach((button) => {
    if (button.dataset.screen === name) {
      button.setAttribute("aria-current", "page");
    } else {
      button.removeAttribute("aria-current");
    }
  });

  window.location.hash = name;
  document.getElementById("main").scrollIntoView({ block: "start" });
}

function currentScreenIndex() {
  const active = document.querySelector(".screen.is-active");
  if (!active) {
    return 0;
  }
  return SCREENS.indexOf(active.id.replace("screen-", ""));
}

function step(delta) {
  const next = currentScreenIndex() + delta;
  if (next >= 0 && next < SCREENS.length) {
    showScreen(SCREENS[next]);
  }
}

/* ---------- backend health ---------- */

async function checkHealth() {
  const indicator = document.getElementById("health-indicator");
  const label = document.getElementById("health-text");

  try {
    const response = await fetch("/api/health");
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    indicator.dataset.state = data.status === "ok" ? "ok" : "down";
    label.textContent =
      data.status === "ok" ? "Backend connected" : `Backend: ${data.status}`;
  } catch (error) {
    indicator.dataset.state = "down";
    label.textContent = `Backend unreachable: ${error.message}`;
  }
}

/* ---------- wiring ---------- */

function init() {
  document.querySelectorAll(".navbtn").forEach((button) => {
    button.addEventListener("click", () => showScreen(button.dataset.screen));
  });

  document.querySelectorAll("[data-goto]").forEach((button) => {
    button.addEventListener("click", () => showScreen(button.dataset.goto));
  });

  document.addEventListener("keydown", (event) => {
    const typing =
      event.target instanceof HTMLInputElement ||
      event.target instanceof HTMLTextAreaElement;
    if (typing || event.metaKey || event.ctrlKey || event.altKey) {
      return;
    }
    if (event.key === "ArrowRight") {
      step(1);
    } else if (event.key === "ArrowLeft") {
      step(-1);
    }
  });

  window.addEventListener("hashchange", () => {
    showScreen(window.location.hash.replace("#", ""));
  });

  const initial = window.location.hash.replace("#", "");
  if (SCREENS.includes(initial)) {
    showScreen(initial);
  }

  checkHealth();
}

document.addEventListener("DOMContentLoaded", init);
