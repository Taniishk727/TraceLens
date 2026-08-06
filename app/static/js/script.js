/**
 * TraceLens — Main Script & OSINT Validation Utilities
 * ====================================================
 * Reusable validation functions and form handlers for TraceLens:
 * - Universal Search (/search)
 * - Dedicated Email Search (/email-search)
 * - Dedicated Phone Search (/phone-search)
 */

(function (global) {
  'use strict';

  /**
   * Reusable Email Validation Utility Function
   * @param {string} email
   * @returns {{ valid: boolean, normalized: string, error: string | null }}
   */
  function validateEmail(email) {
    if (email === null || email === undefined) {
      return { valid: false, normalized: '', error: 'Email address is required.' };
    }

    var raw = String(email);
    var normalized = raw.trim().toLowerCase();

    if (!normalized) {
      return { valid: false, normalized: '', error: 'Email address is required.' };
    }

    if (normalized.length > 254) {
      return { valid: false, normalized: normalized, error: 'Email address cannot exceed 254 characters.' };
    }

    if (/\s/.test(normalized)) {
      return { valid: false, normalized: normalized, error: 'Invalid email format.' };
    }

    var parts = normalized.split('@');
    if (parts.length !== 2) {
      return { valid: false, normalized: normalized, error: 'Invalid email format.' };
    }

    var localPart = parts[0];
    var domainPart = parts[1];

    if (!localPart || !domainPart) {
      return { valid: false, normalized: normalized, error: 'Invalid email format.' };
    }

    if (normalized.indexOf('..') !== -1) {
      return { valid: false, normalized: normalized, error: 'Invalid email format.' };
    }

    if (domainPart.indexOf('.') === -1) {
      return { valid: false, normalized: normalized, error: 'Invalid email format.' };
    }

    if (localPart.charAt(0) === '.' || localPart.charAt(localPart.length - 1) === '.') {
      return { valid: false, normalized: normalized, error: 'Invalid email format.' };
    }

    var localRegex = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;
    if (!localRegex.test(localPart)) {
      return { valid: false, normalized: normalized, error: 'Invalid email format.' };
    }

    var domainLabels = domainPart.split('.');
    for (var i = 0; i < domainLabels.length; i++) {
      var label = domainLabels[i];
      if (!label || label.charAt(0) === '-' || label.charAt(label.length - 1) === '-') {
        return { valid: false, normalized: normalized, error: 'Invalid email format.' };
      }
      if (!/^[a-z0-9-]+$/.test(label)) {
        return { valid: false, normalized: normalized, error: 'Invalid email format.' };
      }
    }

    var tld = domainLabels[domainLabels.length - 1];
    if (tld.length < 2 || /^\d+$/.test(tld)) {
      return { valid: false, normalized: normalized, error: 'Invalid email format.' };
    }

    var robustRegex = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
    if (!robustRegex.test(normalized)) {
      return { valid: false, normalized: normalized, error: 'Invalid email format.' };
    }

    return {
      valid: true,
      normalized: normalized,
      error: null
    };
  }

  /**
   * Reusable Phone Number Validation Utility Function
   * @param {string} phone
   * @returns {{ valid: boolean, normalized: string, error: string | null }}
   */
  function validatePhoneNumber(phone) {
    if (phone === null || phone === undefined) {
      return { valid: false, normalized: '', error: 'Phone number is required.' };
    }

    var raw = String(phone).trim();
    if (!raw) {
      return { valid: false, normalized: '', error: 'Phone number is required.' };
    }

    // Reject letters
    if (/[a-zA-Z]/.test(raw)) {
      return { valid: false, normalized: raw, error: 'Invalid phone number format.' };
    }

    var hasPlus = raw.startsWith('+');
    var digitsOnly = raw.replace(/[^\d]/g, '');

    if (!digitsOnly) {
      return { valid: false, normalized: raw, error: 'Phone number is required.' };
    }

    if (digitsOnly.length < 7 || digitsOnly.length > 15) {
      return { valid: false, normalized: raw, error: 'Phone number must contain between 7 and 15 digits.' };
    }

    var normalized = hasPlus ? '+' + digitsOnly : digitsOnly;

    return {
      valid: true,
      normalized: normalized,
      error: null
    };
  }

  // Export utilities globally
  global.validateEmail = validateEmail;
  global.validatePhoneNumber = validatePhoneNumber;

  document.addEventListener('DOMContentLoaded', function () {
    // --------------------------------------------------------
    // 1. Universal Search Form (/search)
    // --------------------------------------------------------
    var searchForm = document.querySelector('form[action="/search"]');
    if (searchForm) {
      var searchInput = searchForm.querySelector('input[name="query"]');

      searchForm.addEventListener('submit', function () {
        var queryVal = searchInput ? searchInput.value.trim() : '';
        var emailVal = validateEmail(queryVal);
        var phoneVal = validatePhoneNumber(queryVal);

        if (emailVal.valid && typeof TraceLensEmailLoader !== 'undefined') {
          TraceLensEmailLoader.start(emailVal.normalized);
        } else if (phoneVal.valid && typeof TraceLensPhoneLoader !== 'undefined') {
          TraceLensPhoneLoader.start(phoneVal.normalized);
        } else if (typeof TraceLensLoader !== 'undefined' && window.TL_PLATFORMS) {
          TraceLensLoader.start(window.TL_PLATFORMS);
        }
      });
    }

    // --------------------------------------------------------
    // 2. Dedicated Email Search Form (/email-search)
    // --------------------------------------------------------
    var emailForm = document.getElementById('tl-email-search-form');
    if (emailForm) {
      var emailInput = document.getElementById('tl-email-input');
      var emailSubmitBtn = document.getElementById('tl-email-submit-btn');
      var emailSpinnerEl = document.getElementById('tl-email-btn-spinner');
      var emailBtnTextEl = document.getElementById('tl-email-btn-text');
      var emailErrorMsgEl = document.getElementById('tl-email-error-msg');
      var emailErrorTextEl = document.getElementById('tl-email-error-text');

      if (emailInput && emailSubmitBtn) {
        emailInput.focus();

        function updateEmailValidationState(showInlineError) {
          var val = emailInput.value;
          var res = validateEmail(val);

          if (!val.trim()) {
            emailSubmitBtn.disabled = true;
            emailInput.classList.remove('is-invalid');
            if (emailErrorMsgEl) emailErrorMsgEl.style.display = 'none';
            return res;
          }

          if (res.valid) {
            emailSubmitBtn.disabled = false;
            emailInput.classList.remove('is-invalid');
            if (emailErrorMsgEl) emailErrorMsgEl.style.display = 'none';
          } else {
            emailSubmitBtn.disabled = true;
            if (showInlineError) {
              emailInput.classList.add('is-invalid');
              if (emailErrorMsgEl && emailErrorTextEl) {
                emailErrorTextEl.textContent = res.error || 'Please enter a valid email address.';
                emailErrorMsgEl.style.display = 'block';
              }
            } else {
              emailInput.classList.remove('is-invalid');
              if (emailErrorMsgEl) emailErrorMsgEl.style.display = 'none';
            }
          }
          return res;
        }

        emailInput.addEventListener('input', function () { updateEmailValidationState(true); });
        emailInput.addEventListener('keyup', function () { updateEmailValidationState(true); });
        emailInput.addEventListener('paste', function () { setTimeout(function () { updateEmailValidationState(true); }, 10); });
        emailInput.addEventListener('blur', function () { if (emailInput.value.trim().length > 0) updateEmailValidationState(true); });

        if (emailInput.value.trim().length > 0) updateEmailValidationState(true);
        else emailSubmitBtn.disabled = true;

        emailForm.addEventListener('submit', function (e) {
          var res = validateEmail(emailInput.value);
          if (!res.valid) {
            e.preventDefault();
            updateEmailValidationState(true);
            emailInput.focus();
            return false;
          }

          emailInput.value = res.normalized;
          emailSubmitBtn.disabled = true;
          if (emailSpinnerEl) emailSpinnerEl.classList.remove('d-none');
          if (emailBtnTextEl) emailBtnTextEl.innerHTML = 'Starting Investigation...';

          if (typeof TraceLensEmailLoader !== 'undefined') {
            TraceLensEmailLoader.start(res.normalized);
          }
        });
      }
    }

    // --------------------------------------------------------
    // 3. Dedicated Phone Search Form (/phone-search)
    // --------------------------------------------------------
    var phoneForm = document.getElementById('tl-phone-search-form');
    if (phoneForm) {
      var phoneInput = document.getElementById('tl-phone-input');
      var phoneSubmitBtn = document.getElementById('tl-phone-submit-btn');
      var phoneSpinnerEl = document.getElementById('tl-phone-btn-spinner');
      var phoneBtnTextEl = document.getElementById('tl-phone-btn-text');
      var phoneErrorMsgEl = document.getElementById('tl-phone-error-msg');
      var phoneErrorTextEl = document.getElementById('tl-phone-error-text');

      if (phoneInput && phoneSubmitBtn) {
        phoneInput.focus();

        function updatePhoneValidationState(showInlineError) {
          var val = phoneInput.value;
          var res = validatePhoneNumber(val);

          if (!val.trim()) {
            phoneSubmitBtn.disabled = true;
            phoneInput.classList.remove('is-invalid');
            if (phoneErrorMsgEl) phoneErrorMsgEl.style.display = 'none';
            return res;
          }

          if (res.valid) {
            phoneSubmitBtn.disabled = false;
            phoneInput.classList.remove('is-invalid');
            if (phoneErrorMsgEl) phoneErrorMsgEl.style.display = 'none';
          } else {
            phoneSubmitBtn.disabled = true;
            if (showInlineError) {
              phoneInput.classList.add('is-invalid');
              if (phoneErrorMsgEl && phoneErrorTextEl) {
                phoneErrorTextEl.textContent = res.error || 'Please enter a valid phone number.';
                phoneErrorMsgEl.style.display = 'block';
              }
            } else {
              phoneInput.classList.remove('is-invalid');
              if (phoneErrorMsgEl) phoneErrorMsgEl.style.display = 'none';
            }
          }
          return res;
        }

        phoneInput.addEventListener('input', function () { updatePhoneValidationState(true); });
        phoneInput.addEventListener('keyup', function () { updatePhoneValidationState(true); });
        phoneInput.addEventListener('paste', function () { setTimeout(function () { updatePhoneValidationState(true); }, 10); });
        phoneInput.addEventListener('blur', function () { if (phoneInput.value.trim().length > 0) updatePhoneValidationState(true); });

        if (phoneInput.value.trim().length > 0) updatePhoneValidationState(true);
        else phoneSubmitBtn.disabled = true;

        phoneForm.addEventListener('submit', function (e) {
          var res = validatePhoneNumber(phoneInput.value);
          if (!res.valid) {
            e.preventDefault();
            updatePhoneValidationState(true);
            phoneInput.focus();
            return false;
          }

          phoneInput.value = res.normalized;
          phoneSubmitBtn.disabled = true;
          if (phoneSpinnerEl) phoneSpinnerEl.classList.remove('d-none');
          if (phoneBtnTextEl) phoneBtnTextEl.innerHTML = 'Starting Investigation...';

          if (typeof TraceLensPhoneLoader !== 'undefined') {
            TraceLensPhoneLoader.start(res.normalized);
          }
        });
      }
    }
  });
})(window);
