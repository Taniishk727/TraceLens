/**
 * TraceLens Email OSINT Dedicated Loading Animation
 * =================================================
 * Modern Cyber Intelligence Dashboard Overlay
 *
 * Stage Flow:
 *   1. Email Submitted
 *   2. Verification
 *   3. DNS Intelligence
 *   4. Public Identity
 *   5. Avatar Lookup
 *   6. Breach Intelligence
 *   7. Generating Report
 *
 * Visual States:
 *   - Completed: Green (#10b981) + Checkmark
 *   - Current: Pulsing Cyan (#00f0ff)
 *   - Pending: Dim Slate (#334155)
 *
 * Author: TraceLens OSINT Engine
 */

(function (global) {
  'use strict';

  // Modular Pipeline Configuration Array (Easy to add/remove stages)
  var EMAIL_STAGES = [
    {
      id: 'stage_submitted',
      name: 'Email Submitted',
      collector: 'EmailValidator & Syntax Inspector',
      icon: 'bi-envelope-check-fill',
      duration: 350
    },
    {
      id: 'stage_verification',
      name: 'Verification',
      collector: 'VerificationCollector (SMTP & MX Check)',
      icon: 'bi-shield-check',
      duration: 550
    },
    {
      id: 'stage_dns',
      name: 'DNS Intelligence',
      collector: 'DomainCollector (MX/SPF/DMARC)',
      icon: 'bi-dns-fill',
      duration: 500
    },
    {
      id: 'stage_identity',
      name: 'Public Identity',
      collector: 'IdentityCollector (GitHub, GitLab, Gravatar)',
      icon: 'bi-person-badge-fill',
      duration: 700
    },
    {
      id: 'stage_avatar',
      name: 'Avatar Lookup',
      collector: 'AvatarCollector & Libravatar Engine',
      icon: 'bi-image-fill',
      duration: 500
    },
    {
      id: 'stage_breach',
      name: 'Breach Intelligence',
      collector: 'BreachCollector & HIBP API',
      icon: 'bi-shield-exclamation',
      duration: 450
    },
    {
      id: 'stage_report',
      name: 'Generating Report',
      collector: 'TraceLens Intelligence Synthesizer',
      icon: 'bi-file-earmark-text-fill',
      duration: 400
    }
  ];

  var overlayEl = null;
  var timerInterval = null;
  var stepTimeout = null;
  var startTime = 0;

  var EmailLoader = {
    start: function (targetEmail) {
      if (!targetEmail) targetEmail = 'target@domain.com';
      this.stop(); // Clean up previous instance if any

      // Create Overlay DOM Structure
      overlayEl = document.createElement('div');
      overlayEl.id = 'tl-email-loader-overlay';

      var stagesHtml = EMAIL_STAGES.map(function (stage, idx) {
        return (
          '<div class="tl-stage-card pending" id="node_' + stage.id + '" data-index="' + idx + '">' +
            '<div class="tl-stage-icon-ring">' +
              '<i class="bi ' + stage.icon + '"></i>' +
            '</div>' +
            '<div class="tl-stage-name">' + (idx + 1) + '. ' + stage.name + '</div>' +
            '<div class="tl-stage-status-badge">Pending</div>' +
          '</div>'
        );
      }).join('');

      overlayEl.innerHTML =
        '<svg class="tl-email-svg-connectors">' +
          '<defs>' +
            '<linearGradient id="cyanEmeraldGrad" x1="0%" y1="0%" x2="100%" y2="0%">' +
              '<stop offset="0%" stop-color="#00f0ff" />' +
              '<stop offset="100%" stop-color="#10b981" />' +
            '</linearGradient>' +
          '</defs>' +
          '<line class="tl-email-line-bg" x1="5%" y1="50%" x2="95%" y2="50%" />' +
          '<line class="tl-email-line-active" x1="5%" y1="50%" x2="5%" y2="50%" id="tl-email-active-line" />' +
        '</svg>' +

        '<div class="tl-email-loader-header">' +
          '<div class="tl-email-brand">' +
            '<div class="tl-email-brand-icon"><i class="bi bi-cpu-fill"></i></div>' +
            '<div>' +
              '<h3 class="tl-email-title">TRACELENS // EMAIL OSINT ENGINE</h3>' +
              '<div class="tl-email-subtitle">CYBER INTELLIGENCE DASHBOARD</div>' +
            '</div>' +
          '</div>' +
          '<div class="tl-email-target-pill">' +
            '<i class="bi bi-lock-fill text-info"></i>' +
            '<div>' +
              '<div class="tl-email-target-label">Target Email Address</div>' +
              '<div class="tl-email-target-value">' + escapeHtml(targetEmail) + '</div>' +
            '</div>' +
          '</div>' +
        '</div>' +

        '<div class="tl-email-pipeline-container">' +
          '<div class="tl-email-stages-wrapper" id="tl-email-stages-row">' +
            stagesHtml +
            '<div id="tl-email-packet-core">' +
              '<i class="bi bi-arrow-repeat"></i>' +
              '<span id="tl-packet-text">' + escapeHtml(targetEmail) + '</span>' +
            '</div>' +
          '</div>' +
        '</div>' +

        '<div class="tl-email-loader-footer">' +
          '<div class="tl-email-telemetry-row">' +
            '<div class="tl-email-collector-name" id="tl-email-collector-display">' +
              '<i class="bi bi-gear-wide-connected text-info"></i> INITIALIZING EMAIL PIPELINE...' +
            '</div>' +
            '<div class="tl-email-timer">ELAPSED TIME: <span id="tl-email-timer-val">0.00s</span></div>' +
          '</div>' +
          '<div class="tl-email-progress-wrapper">' +
            '<div class="tl-email-progress-bar-bg">' +
              '<div class="tl-email-progress-bar-fill" id="tl-email-progress-fill"></div>' +
            '</div>' +
            '<div class="tl-email-progress-percent" id="tl-email-progress-num">0%</div>' +
          '</div>' +
        '</div>';

      document.body.appendChild(overlayEl);

      // Start Timer Counter
      startTime = performance.now();
      timerInterval = setInterval(function () {
        var elapsedSec = ((performance.now() - startTime) / 1000).toFixed(2);
        var timerValEl = document.getElementById('tl-email-timer-val');
        if (timerValEl) timerValEl.textContent = elapsedSec + 's';
      }, 30);

      // Run Stage Pipeline Animation
      this._runStageSequence(0);
    },

    _runStageSequence: function (stageIdx) {
      if (stageIdx >= EMAIL_STAGES.length) {
        // All stages complete, stay at 100% until page navigates
        this._updateProgress(100);
        var colEl = document.getElementById('tl-email-collector-display');
        if (colEl) {
          colEl.innerHTML = '<i class="bi bi-check-circle-fill text-success"></i> ANALYSIS COMPLETE — RENDERING REPORT...';
        }
        return;
      }

      var currentStage = EMAIL_STAGES[stageIdx];
      var totalStages = EMAIL_STAGES.length;

      // Update Node States
      EMAIL_STAGES.forEach(function (stg, idx) {
        var nodeEl = document.getElementById('node_' + stg.id);
        if (!nodeEl) return;

        var statusBadge = nodeEl.querySelector('.tl-stage-status-badge');
        var iconRing = nodeEl.querySelector('.tl-stage-icon-ring');

        if (idx < stageIdx) {
          // Completed State (Green + Checkmark)
          nodeEl.className = 'tl-stage-card completed';
          if (statusBadge) statusBadge.textContent = 'Completed';
          if (iconRing) iconRing.innerHTML = '<i class="bi bi-check-lg"></i>';
        } else if (idx === stageIdx) {
          // Current Active State (Pulsing Cyan)
          nodeEl.className = 'tl-stage-card active';
          if (statusBadge) statusBadge.textContent = 'Scanning...';
          if (iconRing) iconRing.innerHTML = '<i class="bi ' + stg.icon + '"></i>';
        } else {
          // Pending State (Dim)
          nodeEl.className = 'tl-stage-card pending';
          if (statusBadge) statusBadge.textContent = 'Pending';
          if (iconRing) iconRing.innerHTML = '<i class="bi ' + stg.icon + '"></i>';
        }
      });

      // Update Collector Name Telemetry
      var colDisplay = document.getElementById('tl-email-collector-display');
      if (colDisplay) {
        colDisplay.innerHTML =
          '<i class="bi bi-cpu text-info"></i> EXECUTING: <span style="color:#00f0ff;">' +
          escapeHtml(currentStage.collector) +
          '</span>';
      }

      // Update Progress %
      var percent = Math.round(((stageIdx + 1) / totalStages) * 100);
      this._updateProgress(percent);

      // Move Glowing Packet Core to active node position
      this._movePacketToNode(stageIdx);

      // Schedule next stage transition
      var self = this;
      stepTimeout = setTimeout(function () {
        self._runStageSequence(stageIdx + 1);
      }, currentStage.duration);
    },

    _movePacketToNode: function (nodeIdx) {
      var activeNode = document.getElementById('node_' + EMAIL_STAGES[nodeIdx].id);
      var wrapper = document.getElementById('tl-email-stages-row');
      var packet = document.getElementById('tl-email-packet-core');
      var activeLine = document.getElementById('tl-email-active-line');

      if (activeNode && wrapper && packet) {
        var nodeRect = activeNode.getBoundingClientRect();
        var wrapperRect = wrapper.getBoundingClientRect();

        var relativeLeft = nodeRect.left - wrapperRect.left + nodeRect.width / 2;
        packet.style.left = relativeLeft + 'px';

        if (activeLine) {
          var linePercent = ((nodeIdx + 0.5) / EMAIL_STAGES.length) * 100;
          activeLine.setAttribute('x2', linePercent + '%');
        }
      }
    },

    _updateProgress: function (percent) {
      var fillEl = document.getElementById('tl-email-progress-fill');
      var numEl = document.getElementById('tl-email-progress-num');
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
        }, 500);
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

  global.TraceLensEmailLoader = EmailLoader;
})(window);
