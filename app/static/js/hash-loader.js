/**
 * TraceLens Hash OSINT Dedicated Loading Animation
 * ================================================
 * Cyber Intelligence Dashboard Loader for Hash Investigation
 *
 * Stage Flow:
 *   1. Hash Received (Input & Whitespace Trimming)
 *   2. Validating Format (Hex / Base64 / Structured Inspection)
 *   3. Scanning Signatures (Pattern & Prefix Registry Matching)
 *   4. Ambiguity Resolution (Evaluating Candidates & Confidence Rules)
 *   5. Final Synthesis (Assembly of Properties & Matches)
 *
 * Visual States:
 *   - Completed: Emerald Green (#10b981) + Checkmark
 *   - Active: Pulsing Cyan (#00d4ff)
 *   - Pending: Dim Slate (#334155)
 *
 * Author: TraceLens OSINT Engine
 */

(function (global) {
  'use strict';

  var HASH_STAGES = [
    {
      id: 'stage_received',
      name: 'Hash Received',
      collector: 'HashValidator (Trimming & Input Sanity)',
      icon: 'bi-envelope-paper-fill',
      duration: 200
    },
    {
      id: 'stage_validating',
      name: 'Validating Format',
      collector: 'EncodingInspector (Hex / Base64 / Modular Crypt)',
      icon: 'bi-shield-check',
      duration: 250
    },
    {
      id: 'stage_signatures',
      name: 'Scanning Signatures',
      collector: 'SignatureRegistry (Prefix & Regex Scan)',
      icon: 'bi-search',
      duration: 300
    },
    {
      id: 'stage_ambiguity',
      name: 'Ambiguity Resolution',
      collector: 'AmbiguityEngine (Overlapping Candidates & Confidence Rules)',
      icon: 'bi-diagram-3-fill',
      duration: 250
    },
    {
      id: 'stage_lookup',
      name: 'Looking Up Plaintext',
      collector: 'LookupRegistry (Configured Public Hash Databases)',
      icon: 'bi-database-fill-search',
      duration: 350
    },
    {
      id: 'stage_synthesis',
      name: 'Final Synthesis',
      collector: 'TraceLens Hash & Recovery Synthesizer',
      icon: 'bi-file-earmark-code-fill',
      duration: 200
    }
  ];

  var overlayEl = null;
  var timerInterval = null;
  var stepTimeout = null;
  var startTime = 0;

  var HashLoader = {
    start: function (targetHash) {
      if (!targetHash) targetHash = 'HASH_INPUT';
      this.stop(); // Clean up existing overlay if any

      // Create Overlay Element
      overlayEl = document.createElement('div');
      overlayEl.id = 'tl-hash-loader-overlay';

      var stagesHtml = HASH_STAGES.map(function (stage, idx) {
        return (
          '<div class="tl-hash-stage-card pending" id="hash_node_' + stage.id + '" data-index="' + idx + '">' +
            '<div class="tl-hash-stage-icon-ring">' +
              '<i class="bi ' + stage.icon + '"></i>' +
            '</div>' +
            '<div class="tl-hash-stage-name">' + (idx + 1) + '. ' + stage.name + '</div>' +
            '<div class="tl-hash-stage-status-badge">Pending</div>' +
          '</div>'
        );
      }).join('');

      overlayEl.innerHTML =
        '<svg class="tl-hash-svg-connectors">' +
          '<defs>' +
            '<linearGradient id="cyanPurpleGrad" x1="0%" y1="0%" x2="100%" y2="0%">' +
              '<stop offset="0%" stop-color="#00d4ff" />' +
              '<stop offset="100%" stop-color="#a855f7" />' +
            '</linearGradient>' +
          '</defs>' +
          '<line class="tl-hash-line-bg" x1="5%" y1="50%" x2="95%" y2="50%" />' +
          '<line class="tl-hash-line-active" x1="5%" y1="50%" x2="5%" y2="50%" id="tl-hash-active-line" />' +
        '</svg>' +

        '<div class="tl-hash-loader-header">' +
          '<div class="tl-hash-brand">' +
            '<div class="tl-hash-brand-icon"><i class="bi bi-hash"></i></div>' +
            '<div>' +
              '<h3 class="tl-hash-title">TRACELENS // HASH OSINT ENGINE</h3>' +
              '<div class="tl-hash-subtitle">CYBER ALGORITHM IDENTIFIER</div>' +
            '</div>' +
          '</div>' +
          '<div class="tl-hash-target-pill">' +
            '<i class="bi bi-key-fill text-info"></i>' +
            '<div>' +
              '<div class="tl-hash-target-label">Target Hash Input</div>' +
              '<div class="tl-hash-target-value" title="' + escapeHtml(targetHash) + '">' + escapeHtml(targetHash) + '</div>' +
            '</div>' +
          '</div>' +
        '</div>' +

        '<div class="tl-hash-pipeline-container">' +
          '<div class="tl-hash-stages-wrapper" id="tl-hash-stages-row">' +
            stagesHtml +
            '<div id="tl-hash-packet-core">' +
              '<i class="bi bi-cpu"></i>' +
              '<span id="tl-hash-packet-text">ANALYZING</span>' +
            '</div>' +
          '</div>' +
        '</div>' +

        '<div class="tl-hash-loader-footer">' +
          '<div class="tl-hash-telemetry-row">' +
            '<div class="tl-hash-collector-name" id="tl-hash-collector-display">' +
              '<i class="bi bi-gear-wide-connected text-info"></i> INITIALIZING HASH ANALYSIS ENGINE...' +
            '</div>' +
            '<div class="tl-hash-timer">ELAPSED TIME: <span id="tl-hash-timer-val">0.00s</span></div>' +
          '</div>' +
          '<div class="tl-hash-progress-wrapper">' +
            '<div class="tl-hash-progress-bar-bg">' +
              '<div class="tl-hash-progress-bar-fill" id="tl-hash-progress-fill"></div>' +
            '</div>' +
            '<div class="tl-hash-progress-percent" id="tl-hash-progress-num">0%</div>' +
          '</div>' +
        '</div>';

      document.body.appendChild(overlayEl);

      // Start Elapsed Timer
      startTime = performance.now();
      timerInterval = setInterval(function () {
        var elapsedSec = ((performance.now() - startTime) / 1000).toFixed(2);
        var timerValEl = document.getElementById('tl-hash-timer-val');
        if (timerValEl) timerValEl.textContent = elapsedSec + 's';
      }, 30);

      // Run Stage Sequence
      this._runStageSequence(0);
    },

    _runStageSequence: function (stageIdx) {
      if (stageIdx >= HASH_STAGES.length) {
        this._updateProgress(100);
        var colEl = document.getElementById('tl-hash-collector-display');
        if (colEl) {
          colEl.innerHTML = '<i class="bi bi-check-circle-fill text-success"></i> HASH ANALYSIS COMPLETE — RENDERING RESULT...';
        }
        return;
      }

      var currentStage = HASH_STAGES[stageIdx];
      var totalStages = HASH_STAGES.length;

      // Update Node States
      HASH_STAGES.forEach(function (stg, idx) {
        var nodeEl = document.getElementById('hash_node_' + stg.id);
        if (!nodeEl) return;

        var statusBadge = nodeEl.querySelector('.tl-hash-stage-status-badge');
        var iconRing = nodeEl.querySelector('.tl-hash-stage-icon-ring');

        if (idx < stageIdx) {
          // Completed State
          nodeEl.className = 'tl-hash-stage-card completed';
          if (statusBadge) statusBadge.textContent = 'Done';
          if (iconRing) iconRing.innerHTML = '<i class="bi bi-check-lg"></i>';
        } else if (idx === stageIdx) {
          // Active State
          nodeEl.className = 'tl-hash-stage-card active';
          if (statusBadge) statusBadge.textContent = 'Active...';
          if (iconRing) iconRing.innerHTML = '<i class="bi ' + stg.icon + '"></i>';
        } else {
          // Pending State
          nodeEl.className = 'tl-hash-stage-card pending';
          if (statusBadge) statusBadge.textContent = 'Pending';
          if (iconRing) iconRing.innerHTML = '<i class="bi ' + stg.icon + '"></i>';
        }
      });

      // Update Telemetry Text
      var colDisplay = document.getElementById('tl-hash-collector-display');
      if (colDisplay) {
        colDisplay.innerHTML =
          '<i class="bi bi-cpu text-info"></i> EXECUTING: <span style="color:#00d4ff;">' +
          escapeHtml(currentStage.collector) +
          '</span>';
      }

      // Update Progress Percentage
      var percent = Math.round(((stageIdx + 1) / totalStages) * 100);
      this._updateProgress(percent);

      // Move Glowing Packet Core
      this._movePacketToNode(stageIdx);

      // Transition to next stage after duration
      var self = this;
      stepTimeout = setTimeout(function () {
        self._runStageSequence(stageIdx + 1);
      }, currentStage.duration);
    },

    _movePacketToNode: function (nodeIdx) {
      var activeNode = document.getElementById('hash_node_' + HASH_STAGES[nodeIdx].id);
      var wrapper = document.getElementById('tl-hash-stages-row');
      var packet = document.getElementById('tl-hash-packet-core');
      var activeLine = document.getElementById('tl-hash-active-line');

      if (activeNode && wrapper && packet) {
        var nodeRect = activeNode.getBoundingClientRect();
        var wrapperRect = wrapper.getBoundingClientRect();

        var relativeLeft = nodeRect.left - wrapperRect.left + nodeRect.width / 2;
        packet.style.left = relativeLeft + 'px';

        if (activeLine) {
          var linePercent = ((nodeIdx + 0.5) / HASH_STAGES.length) * 100;
          activeLine.setAttribute('x2', linePercent + '%');
        }
      }
    },

    _updateProgress: function (percent) {
      var fillEl = document.getElementById('tl-hash-progress-fill');
      var numEl = document.getElementById('tl-hash-progress-num');
      if (fillEl) fillEl.style.width = percent + '%';
      if (numEl) numEl.textContent = percent + '%';
    },

    stop: function () {
      if (timerInterval) {
        clearInterval(timerInterval);
        timerInterval = null;
      }
      if (stepTimeout) {
        clearTimeout(stepTimeout);
        stepTimeout = null;
      }
      if (overlayEl) {
        overlayEl.style.opacity = '0';
        setTimeout(function () {
          if (overlayEl && overlayEl.parentNode) {
            overlayEl.parentNode.removeChild(overlayEl);
          }
          overlayEl = null;
        }, 400);
      }
    }
  };

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  global.TraceLensHashLoader = HashLoader;
})(window);
