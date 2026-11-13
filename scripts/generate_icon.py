#!/usr/bin/env python3
"""
Generates an ultra-crisp, sovereign geometric vector-rendered emblem for AEGIS-X
in 1024x1024 RGBA master PNG, plus multi-resolution Windows .ico (256, 128, 64, 48, 32, 16)
and favicon.png / logo-512.png for the Web UI.
"""
import math
import os
from PIL import Image, ImageDraw, ImageFilter

def lerp(a, b, t):
    return a + (b - a) * t

def lerp_color(c1, c2, t):
    return tuple(int(lerp(c1[i], c2[i], t)) for i in range(len(c1)))

def generate_master_emblem(size=1024):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    cx, cy = size / 2, size / 2

    # 1. Outer ambient glow layer
    glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    gd.ellipse([size*0.09, size*0.09, size*0.91, size*0.91], fill=(0, 229, 255, 75))
    gd.ellipse([size*0.18, size*0.18, size*0.82, size*0.82], fill=(99, 102, 241, 90))
    glow = glow.filter(ImageFilter.GaussianBlur(radius=size * 0.045))
    img = Image.alpha_composite(img, glow)

    # 2. Rounded squircle obsidian titanium chassis
    base = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    bd = ImageDraw.Draw(base)
    margin = int(size * 0.075)
    radius = int(size * 0.215)

    # Vertical gradient fill inside squircle mask
    mask = Image.new("L", (size, size), 0)
    md = ImageDraw.Draw(mask)
    md.rounded_rectangle([margin, margin, size - margin, size - margin], radius=radius, fill=255)

    grad = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    px = grad.load()
    top_col = (11, 17, 34, 255)
    mid_col = (6, 10, 21, 255)
    bot_col = (3, 6, 14, 255)
    for y in range(margin, size - margin):
        t = (y - margin) / max(1, (size - 2 * margin))
        if t < 0.5:
            c = lerp_color(top_col, mid_col, t * 2)
        else:
            c = lerp_color(mid_col, bot_col, (t - 0.5) * 2)
        for x in range(margin, size - margin):
            # Subtle radial cyan highlight near upper center
            dx = (x - cx) / (size * 0.45)
            dy = (y - size * 0.30) / (size * 0.45)
            dist = math.sqrt(dx*dx + dy*dy)
            boost = max(0.0, 1.0 - dist) ** 2.2
            r = min(255, int(c[0] + 18 * boost))
            g = min(255, int(c[1] + 58 * boost))
            b = min(255, int(c[2] + 92 * boost))
            px[x, y] = (r, g, b, 255)

    chassis = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    chassis.paste(grad, (0, 0), mask)

    # Metallic dual-bevel border on squircle
    cd = ImageDraw.Draw(chassis)
    cd.rounded_rectangle(
        [margin, margin, size - margin, size - margin],
        radius=radius,
        outline=(0, 229, 255, 210),
        width=max(2, int(size * 0.012)),
    )
    in_m = margin + int(size * 0.018)
    cd.rounded_rectangle(
        [in_m, in_m, size - in_m, size - in_m],
        radius=radius - int(size * 0.014),
        outline=(99, 102, 241, 110),
        width=max(1, int(size * 0.005)),
    )
    img = Image.alpha_composite(img, chassis)

    # 3. Precision Radar Ring & Telemetry Ticks
    radar = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    rd = ImageDraw.Draw(radar)
    ring_r = size * 0.355
    rd.ellipse(
        [cx - ring_r, cy - ring_r, cx + ring_r, cy + ring_r],
        outline=(30, 64, 110, 150),
        width=max(2, int(size * 0.004)),
    )
    for deg in range(0, 360, 15):
        ang = math.radians(deg)
        inner = ring_r * (0.93 if deg % 45 == 0 else 0.96)
        outer = ring_r * (1.02 if deg % 45 == 0 else 1.0)
        x1, y1 = cx + inner * math.cos(ang), cy + inner * math.sin(ang)
        x2, y2 = cx + outer * math.cos(ang), cy + outer * math.sin(ang)
        col = (0, 240, 255, 220) if deg % 90 == 0 else (56, 189, 248, 120)
        w = max(2, int(size * (0.007 if deg % 90 == 0 else 0.0035)))
        rd.line([(x1, y1), (x2, y2)], fill=col, width=w)
    img = Image.alpha_composite(img, radar)

    # 4. Hexagonal Sovereign Aegis Shield Polygon
    shield_layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    sd = ImageDraw.Draw(shield_layer)
    sh_pts = [
        (cx, size * 0.175),               # Top apex
        (size * 0.775, size * 0.285),     # Upper right shoulder
        (size * 0.745, size * 0.585),     # Mid-lower right
        (cx, size * 0.835),               # Bottom spear point
        (size * 0.255, size * 0.585),     # Mid-lower left
        (size * 0.225, size * 0.285),     # Upper left shoulder
    ]
    sd.polygon(sh_pts, fill=(8, 22, 44, 235))

    # Left/right facet shading for 3D crystalline depth
    left_facet = [sh_pts[0], (cx, size * 0.50), sh_pts[3], sh_pts[4], sh_pts[5]]
    right_facet = [sh_pts[0], sh_pts[1], sh_pts[2], sh_pts[3], (cx, size * 0.50)]
    sd.polygon(left_facet, fill=(14, 38, 72, 185))
    sd.polygon(right_facet, fill=(6, 17, 36, 210))

    # Shield glowing neon cyan + electric emerald outline
    shield_glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    sgd = ImageDraw.Draw(shield_glow)
    sgd.line(sh_pts + [sh_pts[0]], fill=(0, 238, 255, 220), width=max(4, int(size * 0.022)), joint="curve")
    shield_glow = shield_glow.filter(ImageFilter.GaussianBlur(radius=size * 0.016))
    img = Image.alpha_composite(img, shield_glow)
    img = Image.alpha_composite(img, shield_layer)

    edge = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    ed = ImageDraw.Draw(edge)
    ed.line(sh_pts + [sh_pts[0]], fill=(56, 248, 255, 255), width=max(3, int(size * 0.013)), joint="curve")

    # Inner shield trim
    in_pts = [
        (cx, size * 0.225),
        (size * 0.725, size * 0.318),
        (size * 0.700, size * 0.565),
        (cx, size * 0.778),
        (size * 0.300, size * 0.565),
        (size * 0.275, size * 0.318),
    ]
    ed.line(in_pts + [in_pts[0]], fill=(99, 102, 241, 190), width=max(2, int(size * 0.006)))

    # 5. Central "AEGIS-X" Cybernetic Core ("A" + Pulse Waveform + Neural Node)
    # Stylized 'A' chevron blades
    blade_left = [
        (cx, size * 0.285),
        (cx - size * 0.032, size * 0.285),
        (size * 0.355, size * 0.635),
        (size * 0.418, size * 0.635),
        (cx, size * 0.382),
    ]
    blade_right = [
        (cx, size * 0.285),
        (cx + size * 0.032, size * 0.285),
        (size * 0.645, size * 0.635),
        (size * 0.582, size * 0.635),
        (cx, size * 0.382),
    ]
    ed.polygon(blade_left, fill=(224, 252, 255, 255))
    ed.polygon(blade_right, fill=(0, 229, 255, 255))

    # Packet-pulse crossbar (Wireshark / IDS deep packet heartbeat)
    pulse_pts = [
        (size * 0.335, size * 0.525),
        (size * 0.435, size * 0.525),
        (size * 0.468, size * 0.455),
        (cx, size * 0.595),
        (size * 0.538, size * 0.435),
        (size * 0.570, size * 0.525),
        (size * 0.665, size * 0.525),
    ]
    pulse_glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    pgd = ImageDraw.Draw(pulse_glow)
    pgd.line(pulse_pts, fill=(16, 245, 160, 235), width=max(4, int(size * 0.022)))
    pulse_glow = pulse_glow.filter(ImageFilter.GaussianBlur(radius=size * 0.012))
    img = Image.alpha_composite(img, pulse_glow)

    ed.line(pulse_pts, fill=(52, 255, 182, 255), width=max(3, int(size * 0.012)))

    # Core glowing quantum node at top of A and bottom spear
    for (nx, ny, nr, col) in [
        (cx, size * 0.285, size * 0.018, (255, 255, 255, 255)),
        (cx, size * 0.688, size * 0.024, (0, 240, 255, 255)),
    ]:
        ed.ellipse([nx - nr, ny - nr, nx + nr, ny + nr], fill=col)

    img = Image.alpha_composite(img, edge)
    return img

def main():
    out_dir = "/home/user/webapp/web/assets"
    build_dir = "/home/user/webapp/build"
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(build_dir, exist_ok=True)

    master = generate_master_emblem(1024)
    master_512 = master.resize((512, 512), Image.Resampling.LANCZOS)
    master_256 = master.resize((256, 256), Image.Resampling.LANCZOS)
    master_64 = master.resize((64, 64), Image.Resampling.LANCZOS)

    master_512.save(os.path.join(out_dir, "aegisx-logo-512.png"), "PNG")
    master_256.save(os.path.join(out_dir, "aegisx-logo-256.png"), "PNG")
    master_64.save(os.path.join(out_dir, "favicon.png"), "PNG")

    ico_path_assets = os.path.join(out_dir, "aegisx.ico")
    ico_path_build = os.path.join(build_dir, "aegisx.ico")

    ico_sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
    master.save(ico_path_assets, format="ICO", sizes=ico_sizes)
    master.save(ico_path_build, format="ICO", sizes=ico_sizes)
    print("Generated icons successfully:", ico_path_build, os.path.getsize(ico_path_build), "bytes")

if __name__ == "__main__":
    main()
