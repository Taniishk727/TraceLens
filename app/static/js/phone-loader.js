/**
 * TraceLens Phone OSINT Dedicated Loading Animation
 * =================================================
 * Modern Cyber Intelligence Dashboard Overlay for Phone Investigations
 */

(function (global) {
  'use strict';

  var PHONE_STAGES = [
    {
      id: 'stage_phone_submitted',
      name: 'Phone Submitted',
      collector: 'PhoneValidator & Syntax Inspector',
      icon: 'bi-telephone-check-fill',
      duration: 350
    },
    {
      id: 'stage_phone_format',
      name: 'Format & Region',
      collector: 'E.164 Normalizer & Geocoder',
      icon: 'bi-globe2',
      duration: 500
    },
    {
      id: 'stage_phone_carrier',
      name: 'Carrier Intelligence',
      collector: 'CarrierCollector (MNO & Line Type)',
      icon: 'bi-reception-4',
      duration: 550
    },
    {
      id: 'stage_phone_timezone',
      name: 'Timezone & Routing',
      collector: 'Timezone & Country Code Engine',
      icon: 'bi-clock-history',
      duration: 450
    },
    {
      id: 'stage_phone_risk',
      name: 'Risk Assessment',
      collector: 'Risk & Fraud Analysis Engine',
      icon: 'bi-shield-exclamation',
      duration: 450
    },
    {
      id: 'stage_phone_report',
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

  var PhoneLoader = {
    start: function (targetPhone) {
      if (!targetPhone) targetPhone = '+14155552671';
      this.stop(); // Clean up previous instance

      overlayEl = document.createElement('div');
      overlayEl.id = 'tl-email-loader-overlay'; // reuse overlay styling structure

      var stagesHtml = PHONE_STAGES.map(function (stage, idx) {
        return (
          '<div class="tl-stage-card pending" id="phone_node_' + stage.id + '" data-index="' + idx + '">' +
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
          '<line class="tl-email-line-active" x1="5%" y1="50%" x2="5%" y2="50%" id="tl-phone-active-line" />' +
        '</svg>' +

        '<div class="tl-email-loader-header">' +
          '<div class="tl-email-brand">' +
            '<div class="tl-email-brand-icon"><i class="bi bi-telephone-fill"></i></div>' +
            '<div>' +
              '<h3 class="tl-email-title">TRACELENS // PHONE OSINT ENGINE</h3>' +
              '<div class="tl-email-subtitle">TELECOM INTELLIGENCE DASHBOARD</div>' +
            '</div>' +
          '</div>' +
          '<div class="tl-email-target-pill">' +
            '<i class="bi bi-shield-lock-fill text-info"></i>' +
            '<div>' +
              '<div class="tl-email-target-label">Target Phone Number</div>' +
              '<div class="tl-email-target-value">' + escapeHtml(targetPhone) + '</div>' +
            '</div>' +
          '</div>' +
        '</div>' +

        '<div class="tl-email-pipeline-container">' +
          '<div class="tl-email-stages-wrapper" id="tl-phone-stages-row">' +
            stagesHtml +
            '<div id="tl-email-packet-core">' +
              '<i class="bi bi-arrow-repeat"></i>' +
              '<span id="tl-packet-text">' + escapeHtml(targetPhone) + '</span>' +
            '</div>' +
          '</div>' +
        '</div>' +

        '<div class="tl-email-loader-footer">' +
          '<div class="tl-email-telemetry-row">' +
            '<div class="tl-email-collector-name" id="tl-phone-collector-display">' +
              '<i class="bi bi-gear-wide-connected text-info"></i> INITIALIZING PHONE PIPELINE...' +
            '</div>' +
            '<div class="tl-email-timer">ELAPSED TIME: <span id="tl-phone-timer-val">0.00s</span></div>' +
          '</div>' +
          '<div class="tl-email-progress-wrapper">' +
            '<div class="tl-email-progress-bar-bg">' +
              '<div class="tl-email-progress-bar-fill" id="tl-phone-progress-fill"></div>' +
            '</div>' +
            '<div class="tl-email-progress-percent" id="tl-phone-progress-num">0%</div>' +
          '</div>' +
        '</div>';

      document.body.appendChild(overlayEl);

      startTime = performance.now();
      timerInterval = setInterval(function () {
        var elapsedSec = ((performance.now() - startTime) / 1000).toFixed(2);
        var timerValEl = document.getElementById('tl-phone-timer-val');
        if (timerValEl) timerValEl.textContent = elapsedSec + 's';
      }, 30);

      this._runStageSequence(0);
    },

    _runStageSequence: function (stageIdx) {
      if (stageIdx >= PHONE_STAGES.length) {
        this._updateProgress(100);
        var colEl = document.getElementById('tl-phone-collector-display');
        if (colEl) {
          colEl.innerHTML = '<i class="bi bi-check-circle-fill text-success"></i> TELECOM ANALYSIS COMPLETE — RENDERING REPORT...';
        }
        return;
      }

      var currentStage = PHONE_STAGES[stageIdx];
      var totalStages = PHONE_STAGES.length;

      PHONE_STAGES.forEach(function (stg, idx) {
        var nodeEl = document.getElementById('phone_node_' + stg.id);
        if (!nodeEl) return;

        var statusBadge = nodeEl.querySelector('.tl-stage-status-badge');
        var iconRing = nodeEl.querySelector('.tl-stage-icon-ring');

        if (idx < stageIdx) {
          nodeEl.className = 'tl-stage-card completed';
          if (statusBadge) statusBadge.textContent = 'Completed';
          if (iconRing) iconRing.innerHTML = '<i class="bi bi-check-lg"></i>';
        } else if (idx === stageIdx) {
          nodeEl.className = 'tl-stage-card active';
          if (statusBadge) statusBadge.textContent = 'Scanning...';
          if (iconRing) iconRing.innerHTML = '<i class="bi ' + stg.icon + '"></i>';
        } else {
          nodeEl.className = 'tl-stage-card pending';
          if (statusBadge) statusBadge.textContent = 'Pending';
          if (iconRing) iconRing.innerHTML = '<i class="bi ' + stg.icon + '"></i>';
        }
      });

      var colDisplay = document.getElementById('tl-phone-collector-display');
      if (colDisplay) {
        colDisplay.innerHTML =
          '<i class="bi bi-cpu text-info"></i> EXECUTING: <span style="color:#00f0ff;">' +
          escapeHtml(currentStage.collector) +
          '</span>';
      }

      var percent = Math.round(((stageIdx + 1) / totalStages) * 100);
      this._updateProgress(percent);
      this._movePacketToNode(stageIdx);

      var self = this;
      stepTimeout = setTimeout(function () {
        self._runStageSequence(stageIdx + 1);
      }, currentStage.duration);
    },

    _movePacketToNode: function (nodeIdx) {
      var activeNode = document.getElementById('phone_node_' + PHONE_STAGES[nodeIdx].id);
      var wrapper = document.getElementById('tl-phone-stages-row');
      var packet = document.getElementById('tl-email-packet-core');
      var activeLine = document.getElementById('tl-phone-active-line');

      if (activeNode && wrapper && packet) {
        var nodeRect = activeNode.getBoundingClientRect();
        var wrapperRect = wrapper.getBoundingClientRect();

        var relativeLeft = nodeRect.left - wrapperRect.left + nodeRect.width / 2;
        packet.style.left = relativeLeft + 'px';

        if (activeLine) {
          var linePercent = ((nodeIdx + 0.5) / PHONE_STAGES.length) * 100;
          activeLine.setAttribute('x2', linePercent + '%');
        }
      }
    },

    _updateProgress: function (percent) {
      var fillEl = document.getElementById('tl-phone-progress-fill');
      var numEl = document.getElementById('tl-phone-progress-num');
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

  global.TraceLensPhoneLoader = PhoneLoader;
})(window);
