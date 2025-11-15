// -----------------------
// ARP Scan
// -----------------------
async function arpScan() {
    const target = document.getElementById("target").value;

    const res = await fetch("/arp-scan", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({target})
    });

    const data = await res.json();
    document.getElementById("scanResult").textContent =
        JSON.stringify(data, null, 2);
}


// -----------------------
// Build ARP packet
// -----------------------
async function buildARP() {
    const form = document.getElementById("buildForm");
    const formData = new FormData(form);

    const payload = Object.fromEntries(formData.entries());

    const res = await fetch("/build-arp", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(payload)
    });

    const data = await res.json();
    document.getElementById("packetResult").textContent =
        JSON.stringify(data, null, 2);
}


// -----------------------
// Sniff ARP
// -----------------------
async function sniffARP() {
    const res = await fetch("/sniff-arp");
    const data = await res.json();
    document.getElementById("sniffResult").textContent =
        JSON.stringify(data, null, 2);
}
