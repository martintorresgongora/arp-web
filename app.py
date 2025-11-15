from flask import Flask, render_template, request, jsonify
from scapy.all import ARP, Ether, srp, sniff, hexdump

app = Flask(__name__)

# --------------------------
# Página principal
# --------------------------
@app.route("/")
def index():
    return render_template("index.html")


# --------------------------
# ARP scan
# --------------------------
@app.route("/arp-scan", methods=["POST"])
def arp_scan():
    target = request.json.get("target")  # ejemplo 192.168.0.0/24

    paquete = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
    respuestas, _ = srp(paquete, timeout=2, verbose=False)

    dispositivos = []
    for _, r in respuestas:
        dispositivos.append({
            "ip": r.psrc,
            "mac": r.hwsrc
        })

    return jsonify(dispositivos)


# --------------------------
# Crear y mostrar paquete ARP
# --------------------------
@app.route("/build-arp", methods=["POST"])
def build_arp():
    data = request.json
    packet = Ether(dst=data["dst_mac"]) / ARP(
        op=data["op"],
        psrc=data["src_ip"],
        pdst=data["dst_ip"],
        hwsrc=data["src_mac"]
    )

    return jsonify({
        "summary": packet.summary(),
        "fields": packet.show(dump=True),
        "hex": hexdump(packet, dump=True)
    })


# --------------------------
# Sniffing ARP
# --------------------------
@app.route("/sniff-arp")
def sniff_arp():

    packets = sniff(filter="arp", count=1, timeout=5)

    if not packets:
        return jsonify({"packet": None})

    pkt = packets[0]

    return jsonify({
        "summary": pkt.summary(),
        "fields": pkt.show(dump=True)
    })


if __name__ == "__main__":
    app.run(debug=True)
