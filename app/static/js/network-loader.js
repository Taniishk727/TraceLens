/*!
 * TraceLens Network Investigation Loader  (v3 - Professional Edition)
 * ====================================================================
 * Architecture
 * ------------
 *   CONFIG       - Palette, sizes, timing
 *   Util         - Pure maths / canvas helpers
 *   Node         - Network node (infra | platform)
 *   Edge         - Directed link with transient hot brightening
 *   Packet       - In-flight packet (pooled, eased motion)
 *   PacketPool   - Zero-allocation pool
 *   Graph        - Procedural topology builder
 *   Renderer     - Canvas2D draw calls (zero DOM side-effects)
 *   Simulator    - Client-side timing model
 *   Panel        - Right-side DOM panel (state-change only)
 *   Controller   - RAF loop + phase state machine + spawn logic
 *   Loader       - Public API: start / stop
 *
 * Key improvements over v2
 * ------------------------
 *   - True 50/50 load-balancing with anti-clump guard (max 3 consecutive)
 *   - Professional dark palette: #0B1220 bg, #3B82F6 active, #60A5FA packets
 *   - Short natural trails (8-12 px, quadratic opacity fade)
 *   - Per-segment transient line brightening (220 ms cool-down)
 *   - Three-phase eased motion: ease-in -> cruise -> ease-out
 *   - Jittered spawn intervals (~170-240 ms)
 *   - Subtle node 1.05x scale on packet pass-through (180 ms)
 *   - Minimal glow, no neon, no saturated greens/reds
 */
(function (global) {
  'use strict';

  /* ════════════════════════════════════════════════════════════════════
     CONFIG
     ════════════════════════════════════════════════════════════════════ */
  var CFG = {
    BG          : '#0B1220',
    GRID_COLOR  : 'rgba(96,165,250,0.025)',
    GRID_SPACING: 44,

    NODE: {
      infra    : '#60A5FA',
      idle     : '#243447',
      searching: '#3B82F6',
      found    : '#34D399',
      notFound : '#94A3B8',
      unknown  : '#FBBF24',
      error    : '#F87171',
    },

    EDGE_INFRA  : '#1E3A5F',
    EDGE_PLAT   : '#172234',
    EDGE_HOT    : '#3B82F6',
    EDGE_HOT_A  : 0.60,
    EDGE_COOL_MS: 220,

    PKT_COLOR     : '#60A5FA',
    PKT_RADIUS    : 3.8,
    PKT_HALO_R    : 10,
    PKT_HALO_A    : 0.22,

    TRAIL_LEN   : 14,
    TRAIL_MAX_A : 0.35,

    PKT_SPEED_BASE: 0.032,
    PKT_SPEED_RAND: 0.016,

    SPAWN_BASE  : 200,
    SPAWN_JITTER: 70,

    CLUMP_MAX   : 3,

    MAX_PACKETS : 24,

    NODE_SCALE_PEAK : 1.05,
    NODE_SCALE_MS   : 180,
  };

  /* ════════════════════════════════════════════════════════════════════
     UTILITIES
     ════════════════════════════════════════════════════════════════════ */
  var Util = {
    hexToRgba: function (hex, a) {
      var r = parseInt(hex.slice(1, 3), 16);
      var g = parseInt(hex.slice(3, 5), 16);
      var b = parseInt(hex.slice(5, 7), 16);
      return 'rgba(' + r + ',' + g + ',' + b + ',' + a + ')';
    },

    lerp: function (a, b, t) { return a + (b - a) * t; },

    easeInOut: function (t) {
      return t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
    },

    /**
     * Three-phase easing for full-path progress (0..1):
     *   0.00-0.15  ease-in  (accelerate away from client)
     *   0.15-0.85  linear   (cruise through infrastructure)
     *   0.85-1.00  ease-out (decelerate into destination)
     */
    pathEase: function (t) {
      if (t < 0.15) { var s = t / 0.15; return 0.15 * s * s; }
      if (t > 0.85) { var s = (t - 0.85) / 0.15; return 0.85 + 0.15 * (1 - (1 - s) * (1 - s)); }
      return t;
    },

    /** Cross-browser rounded rectangle path (no fill/stroke — caller decides). */
    roundRectPath: function (ctx, x, y, w, h, r) {
      ctx.beginPath();
      ctx.moveTo(x + r, y);
      ctx.lineTo(x + w - r, y);
      ctx.arcTo(x + w, y,     x + w, y + r,     r);
      ctx.lineTo(x + w, y + h - r);
      ctx.arcTo(x + w, y + h, x + w - r, y + h, r);
      ctx.lineTo(x + r, y + h);
      ctx.arcTo(x,     y + h, x,     y + h - r, r);
      ctx.lineTo(x, y + r);
      ctx.arcTo(x,     y,     x + r, y,          r);
      ctx.closePath();
    },

    clamp: function (v, lo, hi) { return v < lo ? lo : v > hi ? hi : v; },

    /** Safe string → DOM id fragment. */
    safeId: function (s) { return 'tlp_' + s.replace(/[^a-zA-Z0-9]/g, '_'); },

    htmlEsc: function (s) {
      return ('' + s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
    },
  };

  /* ════════════════════════════════════════════════════════════════════
     NODE
     ════════════════════════════════════════════════════════════════════ */
  function Node(id, label, nx, ny, type) {
    this.id       = id;
    this.label    = label;
    this.nx       = nx;
    this.ny       = ny;
    this.type     = type;
    this.state    = 'idle';
    this.alpha    = type === 'infra' ? 1 : 0;
    this.pulseOff = Math.random() * Math.PI * 2;
    this.ixId     = 'ix_top';
    this.transport= 'requests';
    this.category = '';
    /* Activation flash state */
    this.activateT = -9999;
  }

  Node.prototype.triggerActivation = function (now) { this.activateT = now; };

  /** 1.0 -> 1.05 -> 1.0 triangle over NODE_SCALE_MS */
  Node.prototype.computeScale = function (now) {
    var age = now - this.activateT;
    if (age < 0 || age > CFG.NODE_SCALE_MS) return 1.0;
    var t = age / CFG.NODE_SCALE_MS;
    var tri = t < 0.5 ? t * 2 : (1 - t) * 2;
    return 1.0 + (CFG.NODE_SCALE_PEAK - 1.0) * tri;
  };

  Node.prototype.radius = function () { return this.type === 'infra' ? 10 : 7; };

  Node.prototype.color = function () {
    return this.type === 'infra'
      ? CFG.NODE.infra
      : (CFG.NODE[this.state] || CFG.NODE.idle);
  };

  /* ════════════════════════════════════════════════════════════════════
     EDGE
     ════════════════════════════════════════════════════════════════════ */
  function Edge(a, b) {
    this.a        = a;
    this.b        = b;
    this.drawn    = (a.type === 'infra' && b.type === 'infra') ? 0 : 1;
    this.alpha    = (a.type === 'infra' && b.type === 'infra') ? 1 : 0;
    this.hotUntil = -1;  // timestamp: edge stays bright until this time
  }

  Edge.prototype.touch = function (now) { this.hotUntil = now + CFG.EDGE_COOL_MS; };

  /* ════════════════════════════════════════════════════════════════════
     PACKET  (pooled — never constructed during the animation loop)
     ════════════════════════════════════════════════════════════════════ */
  function Packet() {
    this.alive    = false;
    this.rawProg  = 0;      // 0..1 normalised (drives pathEase)
    this.progress = 0;      // 0..path.length-1 eased
    this.path     = [];
    this.edges    = [];     // edge parallel array for hot-marking
    this.x        = 0;
    this.y        = 0;
    this.color    = CFG.PKT_COLOR;
    this.speed    = CFG.PKT_SPEED_BASE;
    this.radius   = CFG.PKT_RADIUS;
    this.trail    = [];
    this.trailHead= 0;
    for (var i = 0; i < CFG.TRAIL_LEN; i++) this.trail.push({ x: 0, y: 0 });
  }

  Packet.prototype.reset = function (path, edges, speed) {
    this.alive     = true;
    this.rawProg   = 0;
    this.progress  = 0;
    this.path      = path;
    this.edges     = edges;
    this.color     = CFG.PKT_COLOR;
    this.speed     = speed || CFG.PKT_SPEED_BASE;
    this.radius    = CFG.PKT_RADIUS + (Math.random() - 0.5) * 0.6;
    this.trailHead = 0;
    for (var i = 0; i < this.trail.length; i++) {
      this.trail[i].x = 0;
      this.trail[i].y = 0;
    }
  };

  /* ════════════════════════════════════════════════════════════════════
     PACKET POOL
     ════════════════════════════════════════════════════════════════════ */
  function PacketPool(n) {
    this.pool = [];
    for (var i = 0; i < n; i++) this.pool.push(new Packet());
  }

  PacketPool.prototype.acquire = function () {
    for (var i = 0; i < this.pool.length; i++) {
      if (!this.pool[i].alive) return this.pool[i];
    }
    return null; // pool exhausted — caller silently skips
  };

  PacketPool.prototype.activeCount = function () {
    var n = 0;
    for (var i = 0; i < this.pool.length; i++) if (this.pool[i].alive) n++;
    return n;
  };

  /* ════════════════════════════════════════════════════════════════════
     GRAPH  —  procedural network topology
     ════════════════════════════════════════════════════════════════════
     Layout (normalised coords, canvas occupies left portion):
     ┌──────────────────────────────────────────────────────────────────┐
     │ You ─ GW ─ ISP ─ Core ─ IX-North ─┐ platform fan (upper)       │
     │                       └── IX-South ─┘ platform fan (lower)       │
     └──────────────────────────────────────────────────────────────────┘
  */
  var Graph = {
    build: function (platforms) {
      var nodes   = {};
      var all     = [];
      var edges   = [];
      var edgeMap = {};   // 'a|b' and 'b|a' -> Edge (for hot-marking)

      function mk(id, label, nx, ny, type) {
        var n = new Node(id, label, nx, ny, type);
        nodes[id] = n;
        all.push(n);
        return n;
      }
      function link(aid, bid) {
        if (nodes[aid] && nodes[bid]) {
          var e = new Edge(nodes[aid], nodes[bid]);
          edges.push(e);
          edgeMap[aid + '|' + bid] = e;
          edgeMap[bid + '|' + aid] = e;
        }
      }

      /* ── infrastructure backbone ── */
      mk('user',    'You',              0.04, 0.50, 'infra');
      mk('gw',      'Gateway',          0.13, 0.50, 'infra');
      mk('isp',     'ISP',              0.23, 0.50, 'infra');
      mk('core',    'Core Router',      0.36, 0.50, 'infra');
      mk('ix_top',  'IX North',         0.44, 0.31, 'infra');
      mk('ix_bot',  'IX South',         0.44, 0.69, 'infra');

      link('user', 'gw');
      link('gw',   'isp');
      link('isp',  'core');
      link('core', 'ix_top');
      link('core', 'ix_bot');
      link('ix_top', 'ix_bot');   // vertical backbone

      /* ── sector definitions ──────────────────────────────────────────
         Each category maps to an angular sector (degrees) and radius
         relative to its IX anchor node.
         Upper categories radiate from ix_top; lower from ix_bot.
      ── */
      var UPPER_CATS = ['Security', 'Competitive Programming', 'Coding',
                        'Developer', 'Social', 'Social Media', 'Blogging', 'Design'];

      var SECTORS = {
        // angle0, angle1 in degrees; r = radius in normalised units
        'Security'               : { a0: -92, a1: -68, r: 0.18 },
        'Competitive Programming': { a0: -66, a1: -42, r: 0.24 },
        'Coding'                 : { a0: -66, a1: -42, r: 0.24 },
        'Developer'              : { a0: -38, a1:  26, r: 0.27 },
        'Social'                 : { a0: -24, a1:  22, r: 0.28 },
        'Social Media'           : { a0: -24, a1:  22, r: 0.28 },
        'Blogging'               : { a0:  -2, a1:   2, r: 0.25 },
        'Design'                 : { a0: -38, a1: -22, r: 0.22 },
        'Portfolio'              : { a0:  24, a1:  64, r: 0.26 },
        'Gaming'                 : { a0:  66, a1:  82, r: 0.24 },
        'Research'               : { a0:  84, a1:  96, r: 0.24 },
        'Open Source'            : { a0:  84, a1:  96, r: 0.24 },
      };
      var DEFAULT_SECTOR = { a0: -20, a1: 40, r: 0.25 };

      /* ── group platforms by category ── */
      var groups = {};
      platforms.forEach(function (p) {
        var cat = p.category || 'Other';
        if (!groups[cat]) groups[cat] = [];
        groups[cat].push(p);
      });

      /* ── place platform nodes ── */
      var MIN_X = 0.50, MAX_X = 0.93, MIN_Y = 0.05, MAX_Y = 0.94;

      Object.keys(groups).forEach(function (cat) {
        var group  = groups[cat];
        var sector = SECTORS[cat] || DEFAULT_SECTOR;
        var isUpper = UPPER_CATS.indexOf(cat) >= 0;
        var anchorId = isUpper ? 'ix_top' : 'ix_bot';
        var anchor   = nodes[anchorId];
        var count    = group.length;

        group.forEach(function (p, i) {
          var t   = count === 1 ? 0.5 : i / (count - 1);
          var ang = (sector.a0 + t * (sector.a1 - sector.a0)) * Math.PI / 180;
          // Alternate radii slightly so adjacent nodes don't overlap
          var r   = sector.r + (i % 2 === 0 ? 0 : 0.04);

          var nx = Util.clamp(anchor.nx + Math.cos(ang) * r, MIN_X, MAX_X);
          var ny = Util.clamp(anchor.ny + Math.sin(ang) * r, MIN_Y, MAX_Y);

          var n = mk(p.name, p.name, nx, ny, 'platform');
          n.category  = cat;
          n.transport = p.transport || 'requests';
          n.ixId      = anchorId;

          link(anchorId, p.name);
        });
      });

      return { nodes: nodes, all: all, edges: edges, edgeMap: edgeMap };
    },
  };

  /* ════════════════════════════════════════════════════════════════════
     RENDERER  —  all Canvas2D drawing, zero DOM side-effects
     ════════════════════════════════════════════════════════════════════ */
  function Renderer(canvas) {
    this.canvas = canvas;
    this.ctx    = canvas.getContext('2d');
    this.w      = 0;
    this.h      = 0;
  }

  Renderer.prototype.resize = function () {
    var r   = this.canvas.getBoundingClientRect();
    var dpr = window.devicePixelRatio || 1;
    this.w  = r.width;
    this.h  = r.height;
    this.canvas.width  = Math.round(this.w * dpr);
    this.canvas.height = Math.round(this.h * dpr);
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  };

  Renderer.prototype.px = function (n) { return n * this.w; };
  Renderer.prototype.py = function (n) { return n * this.h; };

  Renderer.prototype.clear = function () {
    var ctx = this.ctx;
    ctx.fillStyle = CFG.BG;
    ctx.fillRect(0, 0, this.w, this.h);
    ctx.globalAlpha = 1;
    ctx.strokeStyle = CFG.GRID_COLOR;
    ctx.lineWidth   = 1;
    ctx.beginPath();
    var sp = CFG.GRID_SPACING;
    for (var x = 0.5; x < this.w; x += sp) { ctx.moveTo(x, 0); ctx.lineTo(x, this.h); }
    for (var y = 0.5; y < this.h; y += sp) { ctx.moveTo(0, y); ctx.lineTo(this.w, y); }
    ctx.stroke();
  };

  Renderer.prototype.drawEdge = function (edge, now) {
    if (edge.alpha < 0.01) return;
    var ctx  = this.ctx;
    var ax   = this.px(edge.a.nx), ay = this.py(edge.a.ny);
    var bx   = this.px(edge.b.nx), by = this.py(edge.b.ny);
    var prog = Util.clamp(edge.drawn, 0, 1);
    var ex   = ax + (bx - ax) * prog;
    var ey   = ay + (by - ay) * prog;

    var isInfra = edge.a.type === 'infra' && edge.b.type === 'infra';

    /* Hotness: 0=cool, 1=freshly touched */
    var hot = 0;
    if (edge.hotUntil > 0 && now < edge.hotUntil) {
      hot = Util.clamp((edge.hotUntil - now) / CFG.EDGE_COOL_MS, 0, 1);
    }

    var baseA   = isInfra ? 0.55 : 0.30;
    ctx.globalAlpha = edge.alpha * Util.lerp(baseA, CFG.EDGE_HOT_A, hot);
    ctx.strokeStyle = hot > 0.05 ? CFG.EDGE_HOT : (isInfra ? CFG.EDGE_INFRA : CFG.EDGE_PLAT);
    ctx.lineWidth   = isInfra ? Util.lerp(1.5, 2.2, hot) : Util.lerp(1.0, 1.6, hot);
    ctx.setLineDash([]);
    ctx.beginPath();
    ctx.moveTo(ax, ay);
    ctx.lineTo(ex, ey);
    ctx.stroke();
    ctx.globalAlpha = 1;
  };

  Renderer.prototype.drawNode = function (node, now) {
    if (node.alpha < 0.02) return;
    var ctx   = this.ctx;
    var scale = node.computeScale(now);
    var x     = this.px(node.nx);
    var y     = this.py(node.ny);
    var r     = node.radius() * scale;
    var col   = node.color();
    var pulse = Math.sin(now * 0.0016 + node.pulseOff) * 0.5 + 0.5;

    ctx.globalAlpha = node.alpha;

    /* Subtle glow - restrained, only infra or non-idle */
    if (node.type === 'infra' || node.state !== 'idle') {
      var glowR  = r * 3.5 + pulse * r;
      var age    = now - node.activateT;
      var flash  = (age >= 0 && age < CFG.NODE_SCALE_MS)
                   ? Util.clamp(1 - age / CFG.NODE_SCALE_MS, 0, 1) : 0;
      var gaBase = node.type === 'infra' ? 0.08 : (node.state === 'searching' ? 0.18 : 0.10);
      var ga     = gaBase + flash * 0.14;
      var grd    = ctx.createRadialGradient(x, y, 0, x, y, glowR);
      grd.addColorStop(0, Util.hexToRgba(col, ga * 2));
      grd.addColorStop(1, 'transparent');
      ctx.fillStyle = grd;
      ctx.beginPath();
      ctx.arc(x, y, glowR, 0, Math.PI * 2);
      ctx.fill();
    }

    /* Single thin searching ring - no flashy pulse */
    if (node.state === 'searching') {
      var ringR = r + 4 + pulse * 5;
      ctx.globalAlpha = node.alpha * (0.45 - pulse * 0.30);
      ctx.strokeStyle = col;
      ctx.lineWidth   = 1;
      ctx.beginPath();
      ctx.arc(x, y, ringR, 0, Math.PI * 2);
      ctx.stroke();
      ctx.globalAlpha = node.alpha;
    }

    ctx.fillStyle   = node.type === 'infra' ? '#0F1E30' : '#0C1825';
    ctx.strokeStyle = col;
    ctx.lineWidth   = node.type === 'infra' ? 2 : 1.5;
    ctx.beginPath();
    ctx.arc(x, y, r, 0, Math.PI * 2);
    ctx.fill();
    ctx.stroke();

    if (node.type === 'infra') {
      ctx.fillStyle   = col;
      ctx.globalAlpha = node.alpha * (0.45 + pulse * 0.35);
      ctx.beginPath();
      ctx.arc(x, y, 2.8, 0, Math.PI * 2);
      ctx.fill();
      ctx.globalAlpha = node.alpha;
    }

    var fs = node.type === 'infra' ? 10 : 9;
    ctx.font      = fs + 'px Inter,monospace';
    ctx.fillStyle = 'rgba(148,180,215,' + (node.alpha * 0.75) + ')';
    ctx.textAlign = 'center';
    ctx.fillText(node.label, x, y + r + 13);

    ctx.globalAlpha = 1;
    ctx.textAlign   = 'left';
  };

  Renderer.prototype.drawPacket = function (pkt) {
    if (!pkt.alive) return;
    var ctx  = this.ctx;
    var col  = pkt.color;
    var tlen = pkt.trail.length;

    /* Short quadratic-fade trail */
    for (var i = 1; i < tlen; i++) {
      var ti = (pkt.trailHead - i + tlen * 2) % tlen;
      var pt = pkt.trail[ti];
      if (pt.x === 0 && pt.y === 0) continue;
      var frac = 1 - i / tlen;
      var ta   = frac * frac * CFG.TRAIL_MAX_A;
      var ts   = pkt.radius * frac * 0.75;
      if (ts < 0.3) continue;
      ctx.globalAlpha = ta;
      ctx.fillStyle   = col;
      ctx.beginPath();
      ctx.arc(pt.x, pt.y, ts, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.globalAlpha = 1;

    /* Very subtle halo */
    var hr   = CFG.PKT_HALO_R;
    var halo = ctx.createRadialGradient(pkt.x, pkt.y, 0, pkt.x, pkt.y, hr);
    halo.addColorStop(0, Util.hexToRgba(col, CFG.PKT_HALO_A));
    halo.addColorStop(1, 'transparent');
    ctx.fillStyle   = halo;
    ctx.globalAlpha = 0.9;
    ctx.beginPath();
    ctx.arc(pkt.x, pkt.y, hr, 0, Math.PI * 2);
    ctx.fill();

    /* Core dot */
    ctx.globalAlpha = 1;
    ctx.fillStyle   = col;
    ctx.beginPath();
    ctx.arc(pkt.x, pkt.y, pkt.radius, 0, Math.PI * 2);
    ctx.fill();

    /* Bright pinpoint centre */
    ctx.fillStyle = 'rgba(255,255,255,0.85)';
    ctx.beginPath();
    ctx.arc(pkt.x, pkt.y, pkt.radius * 0.38, 0, Math.PI * 2);
    ctx.fill();
  };

  Renderer.prototype.drawHUD = function (done, total, elapsed) {
    var ctx = this.ctx;
    var bx  = 20, by = this.h - 38, bw = Math.min(this.w * 0.54, 480), bh = 3;

    Util.roundRectPath(ctx, bx, by, bw, bh, 1.5);
    ctx.fillStyle = 'rgba(255,255,255,0.06)';
    ctx.fill();

    var pct = total > 0 ? done / total : 0;
    if (pct > 0.001) {
      Util.roundRectPath(ctx, bx, by, bw * pct, bh, 1.5);
      var fg = ctx.createLinearGradient(bx, 0, bx + bw, 0);
      fg.addColorStop(0, '#3B82F6');
      fg.addColorStop(1, '#60A5FA');
      ctx.fillStyle = fg;
      ctx.fill();
      var ex = bx + bw * pct;
      ctx.globalAlpha = 0.6;
      ctx.fillStyle   = '#93C5FD';
      ctx.beginPath();
      ctx.arc(ex, by + 1.5, 3.5, 0, Math.PI * 2);
      ctx.fill();
      ctx.globalAlpha = 1;
    }

    ctx.font      = '10px Inter,sans-serif';
    ctx.fillStyle = 'rgba(96,165,250,0.55)';
    ctx.textAlign = 'left';
    ctx.fillText(done + ' / ' + total + ' platforms', bx, by - 8);
    ctx.textAlign = 'right';
    ctx.fillText(elapsed.toFixed(1) + 's', bx + bw, by - 8);
    ctx.textAlign = 'left';
  };

  Renderer.prototype.drawLogo = function (alpha) {
    if (alpha < 0.01) return;
    var ctx = this.ctx;
    ctx.globalAlpha = alpha;

    ctx.fillStyle = '#3B82F6';
    ctx.beginPath();
    ctx.arc(24, 38, 5, 0, Math.PI * 2);
    ctx.fill();

    ctx.font      = 'bold 20px Inter,sans-serif';
    ctx.fillStyle = '#60A5FA';
    ctx.textAlign = 'left';
    ctx.fillText('Trace', 36, 44);
    var tw = ctx.measureText('Trace').width;
    ctx.fillStyle = '#E2E8F0';
    ctx.fillText('Lens', 36 + tw, 44);

    ctx.font      = '10px Inter,sans-serif';
    ctx.fillStyle = 'rgba(96,165,250,0.40)';
    ctx.fillText('OSINT INVESTIGATION ENGINE', 36, 60);

    ctx.globalAlpha = 1;
  };

  /* ════════════════════════════════════════════════════════════════════
     SIMULATOR
     Client-side model that fires onStart/onComplete events at timings
     that match the real engine (16 requests workers + 4 browser workers).
     ════════════════════════════════════════════════════════════════════ */
  function Simulator(platforms) {
    this._sched  = [];
    this._started = false;
    this._t0      = 0;
    this.onStart    = null;
    this.onComplete = null;

    var req = [], brw = [];
    platforms.forEach(function (p) {
      (p.transport === 'browser' ? brw : req).push(p);
    });

    /* Requests: 16 concurrent workers, each completes in 1.5–9 s */
    req.forEach(function (p) {
      var done = 1500 + Math.random() * 7500;
      this._sched.push({ p: p, startAt: 80, doneAt: done, _s: false, _d: false });
    }, this);

    /* Browser: 4 workers — queue jobs through 4 virtual workers */
    var workerFree = [600, 600, 600, 600];
    brw.forEach(function (p, i) {
      var wi      = i % 4;
      var startAt = workerFree[wi];
      var dur     = 5000 + Math.random() * 9000;
      workerFree[wi] = startAt + dur;
      this._sched.push({ p: p, startAt: startAt, doneAt: workerFree[wi], _s: false, _d: false });
    }, this);
  }

  Simulator.prototype.start = function () {
    this._started = true;
    this._t0      = performance.now();
  };

  Simulator.prototype.tick = function (now) {
    if (!this._started) return;
    var elapsed = now - this._t0;
    var self    = this;
    this._sched.forEach(function (item) {
      if (!item._s && elapsed >= item.startAt) {
        item._s = true;
        if (self.onStart) self.onStart(item.p);
      }
      if (!item._d && elapsed >= item.doneAt) {
        item._d = true;
        var r  = Math.random();
        var st = r < 0.36 ? 'found'
               : r < 0.62 ? 'notFound'
               : r < 0.85 ? 'unknown'
               :             'error';
        if (self.onComplete) self.onComplete(item.p, st);
      }
    });
  };

  /* ════════════════════════════════════════════════════════════════════
     PANEL  —  right-side DOM progress panel
     Updates innerHTML only on state change — never touched per-frame.
     ════════════════════════════════════════════════════════════════════ */
  var Panel = {
    _items: {},   // name → DOM element

    build: function (root, platforms) {
      this._items = {};
      var h = '';
      h += '<div style="margin-bottom:22px">';
      h += '<div style="font-size:10px;letter-spacing:2px;color:rgba(96,165,250,.38);margin-bottom:5px;font-family:Inter,sans-serif">TRACELENS</div>';
      h += '<div style="font-size:17px;font-weight:700;color:#E2E8F0;font-family:Inter,sans-serif">Active Investigation</div>';
      h += '</div>';
      h += '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-bottom:18px">';
      h += Panel._card('tl-st-el', 'ELAPSED', '0.0s');
      h += Panel._card('tl-st-dn', 'DONE',    '0');
      h += Panel._card('tl-st-pk', 'PACKETS', '0');
      h += '</div>';
      h += '<div style="margin-bottom:16px">';
      h += '<div style="display:flex;justify-content:space-between;font-size:10px;color:rgba(148,163,184,.45);margin-bottom:6px;font-family:Inter,sans-serif">';
      h += '<span>Progress</span><span id="tl-st-pct">0%</span></div>';
      h += '<div style="height:3px;background:rgba(255,255,255,.06);border-radius:99px;overflow:hidden">';
      h += '<div id="tl-pbar" style="height:100%;width:0;background:linear-gradient(90deg,#3B82F6,#60A5FA);border-radius:99px;transition:width .35s ease"></div>';
      h += '</div></div>';
      h += '<div style="height:1px;background:rgba(96,165,250,.07);margin-bottom:14px"></div>';
      h += '<div style="font-size:10px;letter-spacing:1.5px;color:rgba(96,165,250,.34);margin-bottom:10px;font-family:Inter,sans-serif">PLATFORMS</div>';
      h += '<div id="tl-plat-list" style="display:flex;flex-direction:column;gap:2px;overflow-y:auto;flex:1">';
      platforms.forEach(function (p) {
        var sid = Util.safeId(p.name);
        h += '<div id="' + sid + '" style="display:flex;align-items:center;gap:8px;padding:4px 8px;border-radius:5px;font-family:Inter,sans-serif">';
        h += '<span class="tl-ic">' + Panel.ICONS.idle + '</span>';
        h += '<span style="font-size:11px;color:rgba(148,163,184,.65);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + Util.htmlEsc(p.name) + '</span>';
        h += '</div>';
      });
      h += '</div>';
      root.innerHTML = h;
      platforms.forEach(function (p) {
        var el = document.getElementById(Util.safeId(p.name));
        if (el) Panel._items[p.name] = el;
      });
    },

    ICONS: {
      idle     : '<svg width="12" height="12" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="2.5" fill="rgba(100,116,139,0.45)"/></svg>',
      searching: '<svg class="tl-spin" width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="#60A5FA" stroke-width="1.8" stroke-linecap="round"><circle cx="8" cy="8" r="6"/><path d="M8 4.5v3.5l2.5 1.5"/></svg>',
      done     : '<svg width="12" height="12" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="2.2" fill="rgba(100,116,139,0.3)"/></svg>',
    },

    _card: function (id, label, val) {
      return '<div style="background:rgba(59,130,246,.04);border:1px solid rgba(59,130,246,.12);border-radius:8px;padding:8px 10px">' +
             '<div style="font-size:9px;color:rgba(96,165,250,.38);font-family:Inter,sans-serif;margin-bottom:3px">' + label + '</div>' +
             '<div id="' + id + '" style="font-size:15px;font-weight:700;color:#60A5FA;font-family:monospace">' + val + '</div>' +
             '</div>';
    },

    updatePlatform: function (name, status) {
      var el = Panel._items[name];
      if (!el) return;
      var isSearching = status === 'searching';
      var isDone      = status === 'found' || status === 'notFound' || status === 'unknown' || status === 'error';
      var ic = el.querySelector('.tl-ic');
      var tx = el.querySelector('span:last-child');
      if (!ic || !tx) return;
      if (isSearching) {
        el.style.background = 'rgba(59,130,246,0.07)';
        ic.innerHTML = Panel.ICONS.searching;
        tx.style.color = '#93C5FD';
        tx.style.fontWeight = '600';
        tx.style.opacity = '1';
      } else if (isDone) {
        el.style.background = 'rgba(255,255,255,0.012)';
        ic.innerHTML = Panel.ICONS.done;
        tx.style.color = 'rgba(100,116,139,0.5)';
        tx.style.fontWeight = '400';
        tx.style.opacity = '0.55';
      } else {
        el.style.background = 'transparent';
        ic.innerHTML = Panel.ICONS.idle;
        tx.style.color = 'rgba(148,163,184,0.65)';
        tx.style.fontWeight = '400';
        tx.style.opacity = '0.85';
      }
    },

    updateStats: function (done, total, elapsed, pkts) {
      var q;
      if ((q = document.getElementById('tl-st-el')))  q.textContent = elapsed.toFixed(1) + 's';
      if ((q = document.getElementById('tl-st-dn')))  q.textContent = done;
      if ((q = document.getElementById('tl-st-pk')))  q.textContent = pkts;
      if ((q = document.getElementById('tl-st-pct'))) q.textContent = total > 0 ? Math.round(done / total * 100) + '%' : '0%';
      if ((q = document.getElementById('tl-pbar')))   q.style.width = (total > 0 ? done / total * 100 : 0) + '%';
    },
  };

  /* ════════════════════════════════════════════════════════════════════
     CONTROLLER  —  RAF loop + phase state machine
     Phases: fadein → infra → running
     ════════════════════════════════════════════════════════════════════ */
  function Controller(canvas, platforms) {
    this.R      = new Renderer(canvas);
    this.pool   = new PacketPool(CFG.MAX_PACKETS);
    this.G      = null;
    this.sim    = null;
    this.raf    = null;

    this.phase  = 'fadein';
    this.t0     = 0;
    this.last   = 0;
    this.phaseT = 0;

    this.logoAlpha = 0;
    this.done      = 0;
    this.total     = platforms.length;
    this.platforms = platforms;

    this._starts = [];
    this._dones  = [];

    this.onPlatformStart    = null;
    this.onPlatformComplete = null;

    /* Load-balancer state */
    this._bgSpawnAt = 0;
    this._lastIx    = null;
    this._consec    = 0;

    this._tick = this._tick.bind(this);
  }

  Controller.prototype.start = function () {
    var self = this;
    this.R.resize();
    window.addEventListener('resize', function () { self.R.resize(); });

    this.G   = Graph.build(this.platforms);
    this.sim = new Simulator(this.platforms);

    this.sim.onStart    = function (p)       { self._starts.push(p); };
    this.sim.onComplete = function (p, st)   { self._dones.push({ p: p, st: st }); };

    this.t0      = performance.now();
    this.last    = this.t0;
    this.phaseT  = this.t0;
    this.raf     = requestAnimationFrame(this._tick);
  };

  Controller.prototype._tick = function (now) {
    var dt = Math.min(now - this.last, 100);  // cap for backgrounded tabs
    this.last = now;
    var elapsed = now - this.t0;

    this.sim.tick(now);
    this._flushEvents(now);

    if (this.phase === 'fadein') {
      this.logoAlpha = Util.clamp(elapsed / 550, 0, 1);
      if (elapsed > 750) { this.phase = 'infra'; this.phaseT = now; }

    } else if (this.phase === 'infra') {
      var et = now - this.phaseT;
      /* animate infra edge draw-on */
      this.G.edges.forEach(function (e) {
        if (e.a.type === 'infra' && e.b.type === 'infra' && e.drawn < 1) {
          e.drawn = Util.clamp(e.drawn + dt * 0.0022, 0, 1);
        }
      });
      if (et > 950) {
        this.phase  = 'running';
        this.phaseT = now;
        this.sim.start();
        this._bgSpawnAt = now + 300;
      }

    } else if (this.phase === 'running') {
      this.G.all.forEach(function (n) {
        if (n.type === 'platform' && n.alpha < 1) {
          n.alpha = Util.clamp(n.alpha + dt * 0.0014, 0, 1);
        }
      });
      this.G.edges.forEach(function (e) {
        if (e.b.type === 'platform' && e.b.alpha > 0.2) {
          e.alpha = Util.clamp(e.alpha + dt * 0.004, 0, 1);
          e.drawn = Util.clamp(e.drawn + dt * 0.005, 0, 1);
        }
      });
      this._spawnAmbient(now);
      this._updatePackets(dt, now);
    }

    /* render frame */
    this._render(now, elapsed);
    this.raf = requestAnimationFrame(this._tick);
  };

  Controller.prototype._flushEvents = function (now) {
    while (this._starts.length) {
      var p    = this._starts.shift();
      var node = this.G.nodes[p.name];
      if (node) {
        node.state = 'searching';
        this._spawnToTarget(node, now);
      }
      if (this.onPlatformStart) this.onPlatformStart(p);
    }
    while (this._dones.length) {
      var ev   = this._dones.shift();
      var node = this.G.nodes[ev.p.name];
      if (node) node.state = ev.st;
      this.done++;
      if (this.onPlatformComplete) this.onPlatformComplete(ev.p, ev.st);
    }
  };

  /* 50/50 IX selection with anti-clump guard */
  Controller.prototype._chooseIx = function () {
    var candidate = Math.random() < 0.5 ? 'ix_top' : 'ix_bot';
    if (candidate === this._lastIx && this._consec >= CFG.CLUMP_MAX) {
      candidate = (this._lastIx === 'ix_top') ? 'ix_bot' : 'ix_top';
    }
    if (candidate === this._lastIx) { this._consec++; }
    else { this._consec = 1; this._lastIx = candidate; }
    return candidate;
  };

  /* Build edge-parallel array for hot-marking */
  Controller.prototype._buildEdgeList = function (path) {
    var em = this.G.edgeMap, eList = [];
    for (var i = 0; i < path.length - 1; i++) {
      eList.push(em[path[i].id + '|' + path[i + 1].id] || null);
    }
    return eList;
  };

  /* Spawn packet toward a specific target (event-driven) */
  Controller.prototype._spawnToTarget = function (target, now) {
    var pkt = this.pool.acquire();
    if (!pkt) return;
    var nm   = this.G.nodes;
    var ixId = target.ixId || 'ix_top';
    var fwd  = ['user', 'gw', 'isp', 'core', ixId, target.id];
    var rev  = [target.id, ixId, 'core', 'isp', 'gw', 'user'];
    var path = [];
    fwd.forEach(function (id) { var n = nm[id]; if (n) path.push(n); });
    rev.slice(1).forEach(function (id) { var n = nm[id]; if (n) path.push(n); });
    if (path.length < 2) return;
    pkt.reset(path, this._buildEdgeList(path),
              CFG.PKT_SPEED_BASE + (Math.random() - 0.5) * CFG.PKT_SPEED_RAND);
  };

  /* Jittered ambient spawner - load-balanced across both IX nodes */
  Controller.prototype._spawnAmbient = function (now) {
    if (now < this._bgSpawnAt) return;
    this._bgSpawnAt = now + CFG.SPAWN_BASE + (Math.random() - 0.5) * CFG.SPAWN_JITTER;
    var visible = [];
    for (var i = 0; i < this.G.all.length; i++) {
      if (this.G.all[i].type === 'platform' && this.G.all[i].alpha > 0.5) visible.push(this.G.all[i]);
    }
    if (!visible.length) return;
    var target = visible[Math.floor(Math.random() * visible.length)];
    var pkt    = this.pool.acquire();
    if (!pkt) return;
    var ixId = this._chooseIx();
    var nm   = this.G.nodes;
    var fwd  = ['user', 'gw', 'isp', 'core', ixId, target.id];
    var rev  = [target.id, ixId, 'core', 'isp', 'gw', 'user'];
    var path = [];
    fwd.forEach(function (id) { var n = nm[id]; if (n) path.push(n); });
    rev.slice(1).forEach(function (id) { var n = nm[id]; if (n) path.push(n); });
    if (path.length < 2) return;
    pkt.reset(path, this._buildEdgeList(path),
              CFG.PKT_SPEED_BASE + (Math.random() - 0.5) * CFG.PKT_SPEED_RAND);
  };

  Controller.prototype._updatePackets = function (dt, now) {
    var R   = this.R;
    var all = this.pool.pool;
    for (var pi = 0; pi < all.length; pi++) {
      var pkt = all[pi];
      if (!pkt.alive) continue;
      var maxP = pkt.path.length - 1;
      if (maxP < 1) { pkt.alive = false; continue; }

      /* Advance normalised progress, apply three-phase path easing */
      pkt.rawProg = Util.clamp(
        pkt.rawProg + pkt.speed * (dt / 1000) * 60 / maxP, 0, 1);
      if (pkt.rawProg >= 1) { pkt.alive = false; continue; }
      var easedProg = Util.pathEase(pkt.rawProg) * maxP;

      var si = Math.min(Math.floor(easedProg), maxP - 1);
      var st = Util.easeInOut(easedProg - si);
      var fa = pkt.path[si];
      var to = pkt.path[si + 1] || fa;

      pkt.x = Util.lerp(R.px(fa.nx), R.px(to.nx), st);
      pkt.y = Util.lerp(R.py(fa.ny), R.py(to.ny), st);

      /* Mark current edge as hot */
      var hotEdge = pkt.edges[si] || null;
      if (hotEdge) hotEdge.touch(now);

      /* Trigger node brightening as packet nears the next node */
      var frac = easedProg - si;
      if (frac > 0.85 && to.activateT < now - CFG.NODE_SCALE_MS) {
        to.triggerActivation(now);
      }

      pkt.trail[pkt.trailHead].x = pkt.x;
      pkt.trail[pkt.trailHead].y = pkt.y;
      pkt.trailHead = (pkt.trailHead + 1) % pkt.trail.length;
    }
  };

  Controller.prototype._render = function (now, elapsed) {
    var R = this.R;
    R.clear();
    if (!this.G) return;
    this.G.edges.forEach(function (e)   { R.drawEdge(e, now);  });
    this.G.all.forEach(function (n)     { R.drawNode(n, now);  });
    this.pool.pool.forEach(function (p) { R.drawPacket(p);     });
    if (this.phase === 'running') {
      R.drawHUD(this.done, this.total, (now - this.phaseT) / 1000);
    }
    R.drawLogo(this.logoAlpha);
  };

  Controller.prototype.stop = function () {
    if (this.raf) { cancelAnimationFrame(this.raf); this.raf = null; }
  };

  /* ════════════════════════════════════════════════════════════════════
     TRACELENS LOADER  —  Public API
     Called from script.js on form submit.
     ════════════════════════════════════════════════════════════════════ */
  var Loader = {
    _ctrl    : null,
    _overlay : null,
    _timer   : null,
    _t0      : 0,
    _done    : 0,
    _total   : 0,

    start: function (platforms) {
      if (!platforms || !platforms.length) return;
      this._done  = 0;
      this._total = platforms.length;

      /* ── build overlay DOM ── */
      var ov = document.createElement('div');
      ov.id  = 'tl-overlay';
      ov.style.cssText = [
        'position:fixed', 'inset:0', 'z-index:99999',
        'display:flex',   'align-items:stretch',
        'opacity:0',      'transition:opacity 0.38s ease',
        'pointer-events:all',
      ].join(';');

      /* canvas wrapper */
      var cvWrap = document.createElement('div');
      cvWrap.style.cssText = 'flex:1;min-width:0;background:' + CFG.BG + ';overflow:hidden;position:relative';
      var cv = document.createElement('canvas');
      cv.style.cssText = 'display:block;width:100%;height:100%';
      cvWrap.appendChild(cv);

      var panel = document.createElement('div');
      panel.style.cssText = [
        'width:284px', 'flex-shrink:0',
        'background:#07101A',
        'border-left:1px solid rgba(59,130,246,.1)',
        'padding:22px 18px',
        'display:flex', 'flex-direction:column',
        'overflow:hidden',
      ].join(';');

      ov.appendChild(cvWrap);
      ov.appendChild(panel);
      document.body.appendChild(ov);
      this._overlay = ov;

      /* two rAFs ensure transition runs */
      requestAnimationFrame(function () {
        requestAnimationFrame(function () { ov.style.opacity = '1'; });
      });

      /* build panel content */
      Panel.build(panel, platforms);

      /* ── start animation controller ── */
      var ctrl = new Controller(cv, platforms);
      this._ctrl = ctrl;
      this._t0   = performance.now();

      var self = this;
      ctrl.onPlatformStart    = function (p)       { Panel.updatePlatform(p.name, 'searching'); };
      ctrl.onPlatformComplete = function (p, st)   {
        self._done++;
        Panel.updatePlatform(p.name, st);
      };

      ctrl.start();

      /* stats refresh (lightweight — not per-frame) */
      this._timer = setInterval(function () {
        var elapsed = (performance.now() - self._t0) / 1000;
        var pkts    = ctrl.pool.activeCount();
        Panel.updateStats(self._done, self._total, elapsed, pkts);
      }, 150);
    },

    stop: function () {
      if (this._ctrl)  this._ctrl.stop();
      if (this._timer) { clearInterval(this._timer); this._timer = null; }
      if (this._overlay) {
        var ov = this._overlay;
        ov.style.opacity = '0';
        setTimeout(function () { if (ov.parentNode) ov.parentNode.removeChild(ov); }, 450);
        this._overlay = null;
      }
    },
  };

  global.TraceLensLoader = Loader;

}(window));
