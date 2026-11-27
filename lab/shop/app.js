// Acme Shop storefront: the demo target for Gatecrasher.
// Deliberately careless, like many real apps: the client-side environment key
// is baked in and the plan trait is set straight from the browser.
const FLAGSMITH_ENV_KEY = "__FLAGSMITH_CLIENT_KEY__";
const FLAGSMITH_API = "__FLAGSMITH_API_URL__";
const PRICES = { price_low: "$19.00", price_high: "$29.00" };

function cookie(name) {
  const hit = document.cookie.split("; ").find((c) => c.startsWith(name + "="));
  return hit ? decodeURIComponent(hit.split("=")[1]) : null;
}

// Each visitor gets a random browser-generated ID kept in a cookie.
function visitorId() {
  let id = cookie("acme_visitor");
  if (!id) {
    id = "visitor-" + crypto.randomUUID();
    document.cookie = "acme_visitor=" + id + "; path=/; max-age=31536000; SameSite=Lax";
  }
  return id;
}

function show(id, visible) {
  document.getElementById(id).hidden = !visible;
}

function render() {
  show("premium-export", flagsmith.hasFeature("premium_export"));
  show("admin-link", flagsmith.hasFeature("admin_panel"));
  show("staff-badge", flagsmith.hasFeature("staff_preview"));
  show("ai-badge", flagsmith.hasFeature("early_access_ai"));
  const variant = flagsmith.getValue("pricing_page");
  document.getElementById("price").textContent = PRICES[variant] || PRICES.price_high;
  document.getElementById("variant").textContent = variant || "default";
  document.getElementById("banner").textContent = flagsmith.getValue("banner_text") || "";
  document.getElementById("maintenance").hidden = !flagsmith.hasFeature("maintenance_mode");
}

async function loadCheckout() {
  const res = await fetch("/api/checkout-config");
  const cfg = await res.json();
  const el = document.getElementById("checkout");
  el.textContent = res.ok ? "Payments via " + cfg.provider + " (webhook " + cfg.webhook + ")" : "Checkout unavailable: " + cfg.error;
  el.classList.toggle("bad", !res.ok);
}

async function main() {
  const id = visitorId();
  document.getElementById("visitor").textContent = id;
  const plan = cookie("acme_plan") || "free";
  document.getElementById("plan").value = plan;
  await flagsmith.init({
    environmentID: FLAGSMITH_ENV_KEY,
    api: FLAGSMITH_API,
    identity: id,
    traits: { plan: plan },
    onChange: render,
  });
  render();
  document.getElementById("plan").addEventListener("change", async (e) => {
    document.cookie = "acme_plan=" + e.target.value + "; path=/; max-age=31536000; SameSite=Lax";
    await flagsmith.setTrait("plan", e.target.value);
    render();
  });
  loadCheckout();
}

main();
