// Web Bluetooth side of the provisioning client. The crypto (sealing the
// credentials to the device's endpoint id) lives in the wasm module, built from
// the same Rust crate the device uses to open them.
//
// Flow: enter the networks once, then provision any number of devices with
// them. Each device gets its own row; a failed one can be retried over its
// still-open connection after fixing the networks.
//
// Each message also carries a name and a fresh pairing secret. Endpoint id +
// secret form a single-use pairing ticket: the endpoint id alone is public, so
// it can't be what authorizes control of the device.
import init, {
  service_uuid,
  identity_uuid,
  credentials_uuid,
  status_uuid,
  endpoint_id,
  provision,
  max_networks,
  decode_status,
} from "./wasm/provisioning_web.js";

const $ = (sel) => document.querySelector(sel);
// Characteristic values arrive as DataViews, possibly into a larger buffer.
const bytes = (view) => new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
const $status = $("#status");
const $networks = $("#networks");
const $addNetwork = $("#add-network");
const $provision = $("#provision");
const $nextName = $("#next-name");
const $provisionResult = $("#provision-result");
const $sessions = $("#sessions");
const $known = $("#known");
const $knownList = $("#known-list");
const $forget = $("#forget");

await init();

// --- Networks ---------------------------------------------------------------
// Kept in the page only (not in localStorage): they're WiFi passwords.

function addNetworkRow() {
  const row = document.createElement("div");
  row.className = "network";
  row.innerHTML = `
    <input class="ssid" type="text" maxlength="32" placeholder="network name" autocomplete="off" />
    <input class="password" type="password" maxlength="64" placeholder="password" autocomplete="off" />
    <button type="button" class="link remove">remove</button>`;
  row.querySelector(".remove").addEventListener("click", () => {
    row.remove();
    updateNetworkRows();
  });
  row.querySelector(".ssid").addEventListener("input", updateNetworkRows);
  $networks.append(row);
  updateNetworkRows();
  row.querySelector(".ssid").focus();
}

function updateNetworkRows() {
  const rows = $networks.querySelectorAll(".network");
  rows.forEach((row) => (row.querySelector(".remove").hidden = rows.length === 1));
  $addNetwork.hidden = rows.length >= max_networks();
  $provision.disabled = !navigator.bluetooth || networks().length === 0;
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

$addNetwork.addEventListener("click", addNetworkRow);
addNetworkRow();

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

/** "lamp-1" -> "lamp-2"; names without a trailing number stay. */
function nextName(name) {
  const m = name.match(/^(.*?)(\d+)$/);
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

/** One row per device picked in this page, with its own GATT connection. */
function sessionRow(name) {
  const li = document.createElement("li");
  li.className = "session";
  li.innerHTML = `
    <div class="session-head">
      <strong class="name"></strong>
      <span class="state">connecting</span>
      <button type="button" class="link retry" hidden>retry with current networks</button>
    </div>
    <code class="id">—</code>
    <div class="detail"></div>`;
  li.querySelector(".name").textContent = name;
  $sessions.prepend(li);
  return {
    li,
    setId: (id) => (li.querySelector(".id").textContent = id),
    setState: (state, detail) => {
      const $state = li.querySelector(".state");
      $state.textContent = state;
      $state.className = `state ${state}`;
      li.querySelector(".detail").textContent = detail;
    },
    onRetry: (handler) => li.querySelector(".retry").addEventListener("click", handler),
    showRetry: (show) => (li.querySelector(".retry").hidden = !show),
    showTicket: (ticket) => li.append(ticketElement(ticket)),
  };
}

async function provisionDevice() {
  // The browser shows a picker with only the devices advertising our service.
  // Throws NotFoundError if the user closes it.
  const device = await navigator.bluetooth.requestDevice({
    filters: [{ services: [service_uuid()] }],
  });
  // The typed name, or the BLE name if none.
  const name = $nextName.value.trim() || device.name;
  // Count up right away, so devices provisioned in parallel get distinct names.
  if ($nextName.value.trim()) $nextName.value = nextName(name);
  const row = sessionRow(name);
  let done = false;
  let identity;
  let sent = []; // SSIDs in the last message, to name the one that joined
  let ticket; // valid once the device accepts the message it belongs to

  device.addEventListener("gattserverdisconnected", () => {
    row.showRetry(false);
    // After success the device turns Bluetooth off; anything else is a loss.
    if (!done) row.setState("disconnected", "lost the Bluetooth connection; provision it again");
  });

  try {
    const server = await device.gatt.connect();
    const service = await server.getPrimaryService(service_uuid());
    identity = bytes(await (await service.getCharacteristic(identity_uuid())).readValue());
    const id = endpoint_id(identity);
    row.setId(id);

    const credentialsChar = await service.getCharacteristic(credentials_uuid());
    const statusChar = await service.getCharacteristic(status_uuid());
    statusChar.addEventListener("characteristicvaluechanged", (e) => {
      const status = decode_status(bytes(e.target.value));
      if (status.state === "connected") {
        done = true;
        const ssid = sent[status.network] ?? "?";
        row.setState("connected", `joined ${ssid}, ${status.detail}`);
        row.showTicket(ticket);
        remember(id, name, ssid, ticket);
      } else {
        row.setState(status.state, status.detail);
      }
      row.showRetry(status.state === "failed");
    });
    await statusChar.startNotifications();

    const send = async () => {
      const list = networks();
      if (list.length === 0) throw new Error("enter at least one network first");
      const sealed = provision(
        identity,
        list.map((n) => n.ssid),
        list.map((n) => n.password),
        name,
      );
      sent = list.map((n) => n.ssid);
      ticket = sealed.ticket;
      row.showRetry(false);
      // Up to 443 bytes: longer than the default 20 byte ATT payload, which
      // the browser handles (larger MTU, or a long write) transparently.
      await credentialsChar.writeValueWithResponse(sealed.message);
    };
    row.onRetry(() =>
      send().catch((err) => {
        row.setState("failed", `${err}`);
        row.showRetry(true);
      }),
    );
    row.setState("sending", "encrypting to the endpoint id above");
    await send();
  } catch (err) {
    row.setState("failed", `${err}`);
    console.error(err);
    device.gatt.disconnect();
  }
}

$provision.addEventListener("click", async () => {
  $provisionResult.textContent = "";
  $provisionResult.classList.remove("error");
  try {
    await provisionDevice();
  } catch (err) {
    if (err.name === "NotFoundError") return; // picker closed
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
