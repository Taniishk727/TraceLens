/*!
 * TraceLens Network Investigation Loader
 * =======================================
 * Premium full-screen Canvas animation that visualises an OSINT investigation
 * as packets travelling across a live network topology.
 *
 * Architecture
 * ------------
 *   CONFIG          – Tuning constants (colours, sizes, timing)
 *   Util            – Pure helpers (maths, colour, canvas)
 *   Node            – Network node data (infra | platform)
 *   Edge            – Directed link between two nodes
 *   Packet          – In-flight investigation request (pooled)
 *   PacketPool      – Zero-allocation pool of N Packet objects
 *   Graph           – Procedural network topology builder
 *   Renderer        – All Canvas draw calls (zero DOM manipulation)
 *   Simulator       – Client-side investigation timing model
 *   Panel           – Right-side DOM progress panel (updated on state change)
 *   Controller      – RAF loop + phase state machine
 *   TraceLensLoader – Public API: start(platforms) / stop()
 *
 * Usage (injected by search.html)
 * --------------------------------
 *   window.TraceLensLoader.start(window.TL_PLATFORMS);
 */
(function (global) {
  'use strict';

  /* ════════════════════════════════════════════════════════════════════
     CONFIG
     ════════════════════════════════════════════════════════════════════ */
  var CFG = {
    BG            : '#0B0F14',
    GRID_COLOR    : 'rgba(0,212,255,0.038)',
    GRID_SPACING  : 44,

    // Node state colours
    NODE: {
      infra     : '#00bfff',
      idle      : '#2a3a4a',
      searching : '#00d4ff',
      found     : '#22c55e',
      notFound  : '#ef4444',
      unknown   : '#f59e0b',
      error     : '#f97316',
    },

    // Packet colours
    PKT_REQ : '#00d4ff',   // requests-transport packet
    PKT_BRW : '#a78bfa',   // browser-transport packet

    TRAIL_LEN   : 24,
    MAX_PACKETS : 20,
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
    this.nx       = nx;       // normalised [0, 1] within canvas width
    this.ny       = ny;       // normalised [0, 1] within canvas height
    this.type     = type;     // 'infra' | 'platform'
    this.state    = 'idle';   // idle | searching | found | notFound | unknown | error
    this.alpha    = type === 'infra' ? 1 : 0;   // platforms fade in during run phase
    this.pulseOff = Math.random() * Math.PI * 2; // per-node pulse phase offset
    this.ixId     = 'ix_top'; // which IX hub this platform connects through
    this.transport= 'requests';
    this.category = '';
  }

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
    this.a     = a;
    this.b     = b;
    // Infra–infra edges start drawing immediately; platform edges wait for node fade-in
    this.drawn = (a.type === 'infra' && b.type === 'infra') ? 0 : 1;
    this.alpha = (a.type === 'infra' && b.type === 'infra') ? 1 : 0;
  }

  /* ════════════════════════════════════════════════════════════════════
     PACKET  (pooled — never constructed during the animation loop)
     ════════════════════════════════════════════════════════════════════ */
  function Packet() {
    this.alive    = false;
    this.progress = 0;       // 0 … path.length-1
    this.path     = [];      // array of Node objects (forward + return)
    this.x        = 0;
    this.y        = 0;
    this.color    = CFG.PKT_REQ;
    this.speed    = 0.04;    // progress units per 60-fps frame
    // Ring-buffer trail — never resized after construction
    this.trail    = [];
    this.trailHead= 0;
    for (var i = 0; i < CFG.TRAIL_LEN; i++) this.trail.push({ x: 0, y: 0 });
  }

  Packet.prototype.reset = function (path, color, speed) {
    this.alive     = true;
    this.progress  = 0;
    this.path      = path;
    this.color     = color;
    this.speed     = speed || 0.04;
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
      var nodes = {};   // id → Node
      var all   = [];   // flat list for iteration
      var edges = [];

      /* ── helpers ── */
      function mk(id, label, nx, ny, type) {
        var n = new Node(id, label, nx, ny, type);
        nodes[id] = n;
        all.push(n);
        return n;
      }
      function link(aid, bid) {
        if (nodes[aid] && nodes[bid]) edges.push(new Edge(nodes[aid], nodes[bid]));
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

      return { nodes: nodes, all: all, edges: edges };
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

  /** Convert normalised node coords to canvas pixels. */
  Renderer.prototype.nx = function (n) { return n * this.w; };
  Renderer.prototype.ny = function (n) { return n * this.h; };

  Renderer.prototype.clear = function () {
    var ctx = this.ctx;
    ctx.fillStyle = CFG.BG;
    ctx.fillRect(0, 0, this.w, this.h);

    // Subtle dot grid
    ctx.strokeStyle = CFG.GRID_COLOR;
    ctx.lineWidth   = 1;
    ctx.beginPath();
    var sp = CFG.GRID_SPACING;
    for (var x = 0.5; x < this.w; x += sp) { ctx.moveTo(x, 0); ctx.lineTo(x, this.h); }
    for (var y = 0.5; y < this.h; y += sp) { ctx.moveTo(0, y); ctx.lineTo(this.w, y); }
    ctx.stroke();
  };

  Renderer.prototype.drawEdge = function (edge) {
    if (edge.alpha < 0.01) return;
    var ctx  = this.ctx;
    var ax   = this.nx(edge.a.nx), ay = this.ny(edge.a.ny);
    var bx   = this.nx(edge.b.nx), by = this.ny(edge.b.ny);
    var prog = Util.clamp(edge.drawn, 0, 1);
    var ex   = ax + (bx - ax) * prog;
    var ey   = ay + (by - ay) * prog;

    var isInfra = edge.a.type === 'infra' && edge.b.type === 'infra';
    ctx.globalAlpha = edge.alpha * (isInfra ? 0.65 : 0.40);
    ctx.strokeStyle = isInfra ? '#1e3a5f' : '#0f2235';
    ctx.lineWidth   = isInfra ? 1.5 : 1;
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
    var x     = this.nx(node.nx);
    var y     = this.ny(node.ny);
    var r     = node.radius();
    var col   = node.color();
    var pulse = Math.sin(now * 0.0018 + node.pulseOff) * 0.5 + 0.5;

    ctx.globalAlpha = node.alpha;

    /* ── glow (only for non-idle / infrastructure) ── */
    if (node.state !== 'idle' || node.type === 'infra') {
      var gr     = r * 4 + pulse * r * 2;
      var ga     = node.type === 'infra' ? 0.10 : (node.state === 'searching' ? 0.30 : 0.18);
      var grd    = ctx.createRadialGradient(x, y, 0, x, y, gr);
      grd.addColorStop(0, Util.hexToRgba(col, ga));
      grd.addColorStop(1, 'transparent');
      ctx.fillStyle = grd;
      ctx.beginPath();
      ctx.arc(x, y, gr, 0, Math.PI * 2);
      ctx.fill();
    }

    /* ── pulsing search ring ── */
    if (node.state === 'searching') {
      var ringR = r + 5 + pulse * 9;
      ctx.globalAlpha = node.alpha * (0.75 - pulse * 0.55);
      ctx.strokeStyle = col;
      ctx.lineWidth   = 1.2;
      ctx.beginPath();
      ctx.arc(x, y, ringR, 0, Math.PI * 2);
      ctx.stroke();
      ctx.globalAlpha = node.alpha;
    }

    /* ── circle body ── */
    ctx.fillStyle = node.type === 'infra' ? '#0f1e30' : '#0c1825';
    ctx.beginPath();
    ctx.arc(x, y, r, 0, Math.PI * 2);
    ctx.fill();
    ctx.strokeStyle = col;
    ctx.lineWidth   = node.type === 'infra' ? 2 : 1.5;
    ctx.stroke();

    /* ── infra inner pulse dot ── */
    if (node.type === 'infra') {
      ctx.fillStyle   = col;
      ctx.globalAlpha = node.alpha * (0.5 + pulse * 0.5);
      ctx.beginPath();
      ctx.arc(x, y, 3, 0, Math.PI * 2);
      ctx.fill();
      ctx.globalAlpha = node.alpha;
    }

    /* ── label ── */
    var fs = node.type === 'infra' ? 10 : 9;
    ctx.font      = 'bold ' + fs + 'px Inter,monospace';
    ctx.fillStyle = 'rgba(180,210,240,' + (node.alpha * 0.85) + ')';
    ctx.textAlign = 'center';
    ctx.fillText(node.label, x, y + r + 14);

    ctx.globalAlpha = 1;
    ctx.textAlign   = 'left';
  };

  Renderer.prototype.drawPacket = function (pkt) {
    if (!pkt.alive) return;
    var ctx  = this.ctx;
    var col  = pkt.color;
    var tlen = pkt.trail.length;

    /* ── fading trail (ring buffer, no allocation) ── */
    for (var i = 1; i < tlen; i++) {
      var ti = (pkt.trailHead - i + tlen * 2) % tlen;
      var pt = pkt.trail[ti];
      if (pt.x === 0 && pt.y === 0) continue;
      var ta = (1 - i / tlen) * 0.45;
      var ts = 3.5 * (1 - i / tlen);
      if (ts < 0.4) continue;
      ctx.globalAlpha = ta;
      ctx.fillStyle   = col;
      ctx.beginPath();
      ctx.arc(pt.x, pt.y, ts, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.globalAlpha = 1;

    /* ── glow halo ── */
    var halo = ctx.createRadialGradient(pkt.x, pkt.y, 0, pkt.x, pkt.y, 14);
    halo.addColorStop(0, Util.hexToRgba(col, 0.45));
    halo.addColorStop(1, 'transparent');
    ctx.fillStyle   = halo;
    ctx.globalAlpha = 0.75;
    ctx.beginPath();
    ctx.arc(pkt.x, pkt.y, 14, 0, Math.PI * 2);
    ctx.fill();

    /* ── core dot + white centre ── */
    ctx.globalAlpha = 1;
    ctx.fillStyle   = col;
    ctx.beginPath();
    ctx.arc(pkt.x, pkt.y, 4.5, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = '#ffffff';
    ctx.beginPath();
    ctx.arc(pkt.x, pkt.y, 1.7, 0, Math.PI * 2);
    ctx.fill();
  };

  Renderer.prototype.drawHUD = function (done, total, elapsed) {
    var ctx = this.ctx;
    var bx  = 20, by = this.h - 38, bw = Math.min(this.w * 0.54, 480), bh = 4;

    /* ── bar background ── */
    Util.roundRectPath(ctx, bx, by, bw, bh, 2);
    ctx.fillStyle = 'rgba(255,255,255,0.07)';
    ctx.fill();

    /* ── bar fill ── */
    var pct = total > 0 ? done / total : 0;
    if (pct > 0.001) {
      Util.roundRectPath(ctx, bx, by, bw * pct, bh, 2);
      var fg = ctx.createLinearGradient(bx, 0, bx + bw, 0);
      fg.addColorStop(0, '#00d4ff');
      fg.addColorStop(1, '#006eff');
      ctx.fillStyle = fg;
      ctx.fill();

      /* leading-edge glow */
      var ex  = bx + bw * pct;
      var eg  = ctx.createRadialGradient(ex, by + 2, 0, ex, by + 2, 8);
      eg.addColorStop(0, 'rgba(0,212,255,0.75)');
      eg.addColorStop(1, 'transparent');
      ctx.globalAlpha = 0.9;
      ctx.fillStyle   = eg;
      ctx.fillRect(ex - 8, by - 4, 16, 12);
      ctx.globalAlpha = 1;
    }

    /* ── text labels ── */
    ctx.font      = '11px Inter,sans-serif';
    ctx.fillStyle = 'rgba(0,212,255,0.65)';
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

    /* shield dot */
    ctx.fillStyle = '#00d4ff';
    ctx.beginPath();
    ctx.arc(24, 38, 5, 0, Math.PI * 2);
    ctx.fill();

    /* wordmark */
    ctx.font      = 'bold 20px Inter,sans-serif';
    ctx.fillStyle = '#00d4ff';
    ctx.textAlign = 'left';
    ctx.fillText('Trace', 36, 44);

    var tw = ctx.measureText('Trace').width;
    ctx.fillStyle = '#ffffff';
    ctx.fillText('Lens', 36 + tw, 44);

    /* subtitle */
    ctx.font      = '10px Inter,sans-serif';
    ctx.fillStyle = 'rgba(0,212,255,0.45)';
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

      /* header */
      h += '<div style="margin-bottom:22px">';
      h += '<div style="font-size:10px;letter-spacing:2px;color:rgba(0,212,255,.42);margin-bottom:5px;font-family:Inter,sans-serif">TRACELENS</div>';
      h += '<div style="font-size:17px;font-weight:700;color:#fff;font-family:Inter,sans-serif">Active Investigation</div>';
      h += '</div>';

      /* stat cards */
      h += '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-bottom:18px">';
      h += Panel._card('tl-st-el',  'ELAPSED',  '0.0s');
      h += Panel._card('tl-st-dn',  'DONE',     '0');
      h += Panel._card('tl-st-pk',  'PACKETS',  '0');
      h += '</div>';

      /* progress bar */
      h += '<div style="margin-bottom:16px">';
      h += '<div style="display:flex;justify-content:space-between;font-size:10px;color:rgba(140,170,200,.5);margin-bottom:6px;font-family:Inter,sans-serif">';
      h += '<span>Progress</span><span id="tl-st-pct">0%</span></div>';
      h += '<div style="height:3px;background:rgba(255,255,255,.07);border-radius:99px;overflow:hidden">';
      h += '<div id="tl-pbar" style="height:100%;width:0;background:linear-gradient(90deg,#00d4ff,#006eff);border-radius:99px;transition:width .35s ease"></div>';
      h += '</div></div>';

      /* divider */
      h += '<div style="height:1px;background:rgba(0,212,255,.07);margin-bottom:14px"></div>';

      /* platform list */
      h += '<div style="font-size:10px;letter-spacing:1.5px;color:rgba(0,212,255,.38);margin-bottom:10px;font-family:Inter,sans-serif">PLATFORMS</div>';
      h += '<div id="tl-plat-list" style="display:flex;flex-direction:column;gap:2px;overflow-y:auto;flex:1">';

      platforms.forEach(function (p) {
        var sid = Util.safeId(p.name);
        h += '<div id="' + sid + '" style="display:flex;align-items:center;gap:8px;padding:4px 8px;border-radius:5px;font-family:Inter,sans-serif">';
        h += '<span class="tl-ic">' + Panel.ICONS.idle + '</span>';
        h += '<span style="font-size:11px;color:rgba(150,180,210,.7);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + Util.htmlEsc(p.name) + '</span>';
        h += '</div>';
      });

      h += '</div>';
      root.innerHTML = h;

      /* cache element references */
      platforms.forEach(function (p) {
        var el = document.getElementById(Util.safeId(p.name));
        if (el) Panel._items[p.name] = el;
      });
    },

    ICONS: {
      idle: '<svg width="12" height="12" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="2.5" fill="rgba(140, 165, 190, 0.5)"/></svg>',
      searching: '<svg class="tl-spin" width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="#00d4ff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="8" r="6"/><path d="M8 4.5v3.5l2.5 1.5"/></svg>',
      done: '<svg width="12" height="12" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="2.2" fill="rgba(120, 140, 165, 0.4)"/></svg>'
    },

    _card: function (id, label, val) {
      return '<div style="background:rgba(0,212,255,.04);border:1px solid rgba(0,212,255,.1);border-radius:8px;padding:8px 10px">' +
             '<div style="font-size:9px;color:rgba(0,212,255,.4);font-family:Inter,sans-serif;margin-bottom:3px">' + label + '</div>' +
             '<div id="' + id + '" style="font-size:15px;font-weight:700;color:#00d4ff;font-family:monospace">' + val + '</div>' +
             '</div>';
    },

    updatePlatform: function (name, status) {
      var el = Panel._items[name];
      if (!el) return;

      var isSearching = (status === 'searching');
      var isDone = (status === 'found' || status === 'notFound' || status === 'unknown' || status === 'error');

      var ic = el.querySelector('.tl-ic');
      var tx = el.querySelector('span:last-child');
      if (!ic || !tx) return;

      if (isSearching) {
        el.style.background = 'rgba(0, 212, 255, 0.08)';
        ic.innerHTML = Panel.ICONS.searching;
        tx.style.color = '#00d4ff';
        tx.style.fontWeight = '600';
        tx.style.opacity = '1';
      } else if (isDone) {
        el.style.background = 'rgba(255, 255, 255, 0.015)';
        ic.innerHTML = Panel.ICONS.done;
        tx.style.color = 'rgba(120, 140, 165, 0.5)';
        tx.style.fontWeight = '400';
        tx.style.opacity = '0.6';
      } else {
        el.style.background = 'transparent';
        ic.innerHTML = Panel.ICONS.idle;
        tx.style.color = 'rgba(150, 180, 210, 0.7)';
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
    this.R       = new Renderer(canvas);
    this.pool    = new PacketPool(CFG.MAX_PACKETS);
    this.G       = null;
    this.sim     = null;
    this.raf     = null;

    this.phase   = 'fadein';  // fadein | infra | running
    this.t0      = 0;
    this.last    = 0;
    this.phaseT  = 0;

    this.logoAlpha = 0;
    this.done      = 0;
    this.total     = platforms.length;
    this.platforms = platforms;

    /* pending event queues (simulator → controller) */
    this._starts  = [];
    this._dones   = [];

    /* external hooks (controller → panel) */
    this.onPlatformStart    = null;
    this.onPlatformComplete = null;

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

    /* advance simulation */
    this.sim.tick(now);

    /* drain event queues */
    this._flushEvents();

    /* phase state machine */
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
      if (et > 950) { this.phase = 'running'; this.phaseT = now; this.sim.start(); }

    } else if (this.phase === 'running') {
      /* fade in platform nodes */
      this.G.all.forEach(function (n) {
        if (n.type === 'platform' && n.alpha < 1) {
          n.alpha = Util.clamp(n.alpha + dt * 0.0014, 0, 1);
        }
      });
      /* animate platform edge draw-on (triggered once node is visible) */
      this.G.edges.forEach(function (e) {
        if (e.b.type === 'platform' && e.b.alpha > 0.2) {
          e.alpha = Util.clamp(e.alpha + dt * 0.004, 0, 1);
          e.drawn = Util.clamp(e.drawn + dt * 0.005, 0, 1);
        }
      });
      /* update live packets */
      this._updatePackets(dt);
    }

    /* render frame */
    this._render(now, elapsed);
    this.raf = requestAnimationFrame(this._tick);
  };

  Controller.prototype._flushEvents = function () {
    var self = this;

    while (this._starts.length) {
      var p    = this._starts.shift();
      var node = this.G.nodes[p.name];
      if (node) {
        node.state = 'searching';
        this._spawn(node, p.transport === 'browser' ? CFG.PKT_BRW : CFG.PKT_REQ);
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

  Controller.prototype._spawn = function (target, color) {
    var pkt = this.pool.acquire();
    if (!pkt) return;

    var nm  = this.G.nodes;
    var ixId = target.ixId || 'ix_top';

    /* forward path: user → gw → isp → core → IX → target */
    var fwd = ['user', 'gw', 'isp', 'core', ixId, target.id];
    /* return path: target → IX → core → isp → gw → user */
    var rev = [target.id, ixId, 'core', 'isp', 'gw', 'user'];

    var path = [];
    fwd.forEach(function (id) { var n = nm[id]; if (n) path.push(n); });
    rev.slice(1).forEach(function (id) { var n = nm[id]; if (n) path.push(n); });

    if (path.length < 2) return;
    pkt.reset(path, color, 0.024 + Math.random() * 0.018);
  };

  Controller.prototype._updatePackets = function (dt) {
    var R  = this.R;
    var lu = Util;
    this.pool.pool.forEach(function (pkt) {
      if (!pkt.alive) return;

      pkt.progress += pkt.speed * (dt / 1000) * 60;
      var maxP = pkt.path.length - 1;

      if (pkt.progress >= maxP) { pkt.alive = false; return; }

      var si  = Math.floor(pkt.progress);
      var st  = lu.easeInOut(pkt.progress - si);
      var fa  = pkt.path[si];
      var to  = pkt.path[Math.min(si + 1, maxP)];

      pkt.x = lu.lerp(R.nx(fa.nx), R.nx(to.nx), st);
      pkt.y = lu.lerp(R.ny(fa.ny), R.ny(to.ny), st);

      /* write to ring-buffer trail */
      pkt.trail[pkt.trailHead].x = pkt.x;
      pkt.trail[pkt.trailHead].y = pkt.y;
      pkt.trailHead = (pkt.trailHead + 1) % pkt.trail.length;
    });
  };

  Controller.prototype._render = function (now, elapsed) {
    var R    = this.R;
    var self = this;

    R.clear();
    if (!this.G) return;

    this.G.edges.forEach(function (e)  { R.drawEdge(e);       });
    this.G.all.forEach(function (n)    { R.drawNode(n, now);  });
    this.pool.pool.forEach(function (p){ R.drawPacket(p);     });

    if (this.phase === 'running') {
      var runSec = (now - this.phaseT) / 1000;
      R.drawHUD(this.done, this.total, runSec);
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
      cvWrap.style.cssText = 'flex:1;min-width:0;background:#0B0F14;overflow:hidden;position:relative';
      var cv = document.createElement('canvas');
      cv.style.cssText = 'display:block;width:100%;height:100%';
      cvWrap.appendChild(cv);

      /* panel */
      var panel = document.createElement('div');
      panel.style.cssText = [
        'width:284px', 'flex-shrink:0',
        'background:#07101a',
        'border-left:1px solid rgba(0,212,255,.1)',
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
