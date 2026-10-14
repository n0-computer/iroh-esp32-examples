// The provisioning page's UI. Everything else (Web Bluetooth, sealing, the
// protocol) is Rust: `iroh-provision`'s client Session over the Web Bluetooth
// transport from `iroh-provision-ble`, exposed by the wasm module.
//
// Flow: enter the networks once, then provision any number of devices with
// them. Each device gets its own row; a failed one can be retried over its
// still-open connection after fixing the networks.
//
// Each device gets a name and a pairing secret. Endpoint id + secret form a
// single-use pairing ticket: the endpoint id alone is public, so it can't be
// what authorizes control of the device. Provisioning a known device again only
// changes its networks: it keeps its name and its ticket stays valid.
import init, { connect_device, max_networks } from "./wasm/provisioning_web.js";

const $ = (sel) => document.querySelector(sel);
const $status = $("#status");
const $networks = $("#networks");
const $addNetwork = $("#add-network");
const $remember = $("#remember");
const $provision = $("#provision");
const $nextName = $("#next-name");
const $provisionResult = $("#provision-result");
const $sessions = $("#sessions");
const $known = $("#known");
const $knownList = $("#known-list");
const $forget = $("#forget");

await init();

// --- Networks ---------------------------------------------------------------
// Remembered in localStorage while "remember" is ticked (the default), so they
// survive reloads. That's plain text in this browser profile, for this origin
// only; unticking deletes them.

const NETWORKS_KEY = "iroh-provisioning:networks";

function loadNetworks() {
  try {
    return JSON.parse(localStorage.getItem(NETWORKS_KEY)) ?? [];
  } catch {
    return [];
  }
}

function saveNetworks() {
  try {
    if ($remember.checked) {
      localStorage.setItem(NETWORKS_KEY, JSON.stringify(networks()));
    } else {
      localStorage.removeItem(NETWORKS_KEY);
    }
  } catch (err) {
    console.warn("could not store networks", err);
  }
}

function addNetworkRow(network = { ssid: "", password: "" }) {
  const row = document.createElement("div");
  row.className = "network";
  row.innerHTML = `
    <input class="ssid" type="text" maxlength="32" placeholder="network name" autocomplete="off" />
    <input class="password" type="password" maxlength="64" placeholder="password" autocomplete="off" />
    <button type="button" class="link remove">remove</button>`;
  row.querySelector(".ssid").value = network.ssid;
  row.querySelector(".password").value = network.password;
  row.querySelector(".remove").addEventListener("click", () => {
    row.remove();
    updateNetworkRows();
  });
  row.addEventListener("input", updateNetworkRows);
  $networks.append(row);
  updateNetworkRows();
  return row;
}

function updateNetworkRows() {
  const rows = $networks.querySelectorAll(".network");
  rows.forEach((row) => (row.querySelector(".remove").hidden = rows.length === 1));
  $addNetwork.hidden = rows.length >= max_networks();
  $provision.disabled = !navigator.bluetooth || networks().length === 0;
  saveNetworks();
}

/** The networks as entered, skipping rows without a name. */
function networks() {
  return [...$networks.querySelectorAll(".network")]
    .map((row) => ({
      ssid: row.querySelector(".ssid").value,
      password: row.querySelector(".password").value,
    }))
    .filter(({ ssid }) => ssid !== "");
}

$addNetwork.addEventListener("click", () => addNetworkRow().querySelector(".ssid").focus());
$remember.addEventListener("change", saveNetworks);
{
  const stored = loadNetworks();
  $remember.checked = true;
  if (stored.length) stored.forEach((n) => addNetworkRow(n));
  else addNetworkRow().querySelector(".ssid").focus();
}

// --- Remembered devices -----------------------------------------------------
// Provisioning is also how the page learns a device's endpoint id: read over
// BLE from the same key that opens the credentials. Remember it, keyed by
// endpoint id, so the device can be dialed via iroh later without BLE.

const KNOWN_KEY = "iroh-provisioning:devices";

function loadKnown() {
  try {
    return JSON.parse(localStorage.getItem(KNOWN_KEY)) ?? {};
  } catch {
    return {};
  }
}

function saveKnown(known) {
  try {
    localStorage.setItem(KNOWN_KEY, JSON.stringify(known));
  } catch (err) {
    console.warn("could not remember devices", err);
  }
  showKnown();
}

function remember(endpointId, name, ssid, ticket) {
  const known = loadKnown();
  known[endpointId] = { name, ssid, ticket, provisioned: new Date().toISOString() };
  saveKnown(known);
}

/** A `pair…` ticket with a copy button. */
function ticketElement(ticket) {
  const div = document.createElement("div");
  div.className = "ticket";
  div.innerHTML = `<code></code><button type="button" class="link">copy</button>`;
  div.querySelector("code").textContent = ticket;
  div.querySelector("button").addEventListener("click", async (e) => {
    try {
      await navigator.clipboard.writeText(ticket);
      e.target.textContent = "copied";
    } catch {
      getSelection().selectAllChildren(div.querySelector("code"));
    }
  });
  return div;
}

/** The first `<kind>-<n>` not taken by a known device or one on this page. */
function suggestName(kind) {
  if (!kind) return undefined;
  const taken = new Set([
    ...Object.values(loadKnown()).map((d) => d.name),
    ...[...rows.values()].map((row) => row.name),
  ]);
  let n = 1;
  while (taken.has(`${kind}-${n}`)) n++;
  return `${kind}-${n}`;
}

/**
 * Count up a number after a separator: "lamp-1" -> "lamp-2", "desk 09" ->
 * "desk 10". Other names stay: in "co2" the digit is part of the name.
 */
function nextName(name) {
  const m = name.match(/^(.*[-_ ])(\d+)$/);
  if (!m) return name;
  return m[1] + String(Number(m[2]) + 1).padStart(m[2].length, "0");
}

function showKnown() {
  const known = Object.entries(loadKnown());
  $known.hidden = known.length === 0;
  $knownList.replaceChildren(
    ...known.map(([id, { name, ssid, ticket }]) => {
      const li = document.createElement("li");
      li.innerHTML = `<div></div><code></code>`;
      li.querySelector("div").textContent = `${name} on ${ssid}`;
      li.querySelector("code").textContent = id;
      if (ticket) li.append(ticketElement(ticket));
      return li;
    }),
  );
}

$forget.addEventListener("click", () => saveKnown({}));
showKnown();

// --- Provisioning sessions --------------------------------------------------

/** Rows by endpoint id: one per device, reused when it's provisioned again. */
const rows = new Map();

/** The row for a device, with its own GATT connection while one is active. */
function sessionRow(id) {
  const li = document.createElement("li");
  li.className = "session";
  li.innerHTML = `
    <div class="session-head">
      <strong class="name"></strong>
      <span class="state"></span>
      <button type="button" class="link retry" hidden>retry with current networks</button>
    </div>
    <code class="id"></code>
    <div class="detail"></div>
    <div class="ticket-slot"></div>`;
  li.querySelector(".id").textContent = id;
  let retry = () => {};
  li.querySelector(".retry").addEventListener("click", () => retry());
  return {
    li,
    name: undefined,
    busy: false, // a provisioning attempt with an open connection
    setName(name) {
      this.name = name;
      li.querySelector(".name").textContent = name;
    },
    setState(state, detail) {
      const $state = li.querySelector(".state");
      $state.textContent = state;
      $state.className = `state ${state}`;
      li.querySelector(".detail").textContent = detail;
    },
    onRetry: (handler) => (retry = handler),
    showRetry: (show) => (li.querySelector(".retry").hidden = !show),
    showTicket: (ticket) =>
      li.querySelector(".ticket-slot").replaceChildren(ticket ? ticketElement(ticket) : ""),
    highlight() {
      li.scrollIntoView({ block: "nearest" });
      li.classList.remove("flash");
      void li.offsetWidth; // restart the animation
      li.classList.add("flash");
    },
  };
}

async function provisionDevice() {
  // Shows the browser's picker; rejects with "no device picked" if closed.
  const device = await connect_device();
  const id = device.endpoint_id;

  // One provisioning per device at a time; picking it again just points at it.
  let row = rows.get(id);
  if (row?.busy) {
    device.disconnect();
    row.highlight();
    return;
  }
  if (!row) {
    row = sessionRow(id);
    rows.set(id, row);
  }
  $sessions.prepend(row.li);

  // A known device keeps its name and ticket: only the networks change. A new
  // one gets the typed name (counting up, so the next device gets the next
  // number), or one after its kind: co2-1, co2-2, ...
  const known = loadKnown()[id];
  let name;
  if (known?.ticket) {
    name = known.name;
  } else {
    const typed = $nextName.value.trim();
    if (typed) $nextName.value = nextName(typed);
    name = typed || suggestName(device.kind) || device.ble_name;
  }
  row.setName(name);
  row.showTicket(known?.ticket);
  row.busy = true;
  const note = known?.ticket ? "provisioning again: name and ticket stay the same" : "";
  row.setState("connecting", note);

  let done = false;
  device.on_disconnect(() => {
    row.busy = false;
    row.showRetry(false);
    // After success the device turns Bluetooth off; anything else is a loss.
    if (!done) row.setState("disconnected", "lost the Bluetooth connection; provision it again");
  });

  const send = async () => {
    const list = networks();
    if (list.length === 0) throw new Error("enter at least one network first");
    row.showRetry(false);
    row.setState("sending", note || "encrypting to the endpoint id above");
    const result = await device.provision(
      list.map((n) => n.ssid),
      list.map((n) => n.password),
      name,
      known?.ticket ?? null,
      (state, detail) => row.setState(state, detail),
    );
    done = true;
    row.setState("connected", `joined ${result.ssid}, IP ${result.ip}`);
    row.showTicket(result.ticket);
    remember(id, name, result.ssid, result.ticket);
  };
  const attempt = () =>
    send().catch((err) => {
      if (done) return;
      row.setState("failed", err.message ?? `${err}`);
      row.showRetry(row.busy);
    });
  row.onRetry(attempt);
  await attempt();
}

$provision.addEventListener("click", async () => {
  $provisionResult.textContent = "";
  $provisionResult.classList.remove("error");
  try {
    await provisionDevice();
  } catch (err) {
    if (`${err.message}`.includes("no device picked")) return; // picker closed
    $provisionResult.textContent = `${err}`;
    $provisionResult.classList.add("error");
    console.error(err);
  }
});

if (!navigator.bluetooth) {
  $status.textContent =
    "This browser has no Web Bluetooth. Use Chrome or Edge on desktop or Android (not iOS, not Firefox).";
} else {
  $status.textContent = "ready";
}
updateNetworkRows();
