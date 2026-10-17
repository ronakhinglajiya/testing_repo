/* Ruko Call Guard: browser app. Captures call audio, sends short chunks to the
 * server for speech-to-text, checks the transcript instantly with ScamRules and
 * periodically with the AI, and raises a full-screen alarm on a scam. */
(function () {
  'use strict';

  var Rules = window.ScamRules;
  var DEMO = window.DemoCalls;

  var CHUNK_SECONDS = 5;          // audio per speech-to-text request
  var TARGET_RATE = 16000;        // Sarvam works best with 16 kHz mono
  var SILENCE_RMS = 0.006;        // skip chunks quieter than this (saves API calls)
  var MAX_PENDING_STT = 4;        // drop audio rather than fall far behind the call
  var AI_MIN_GAP_MS = 4000;       // at most one AI check every 4 s
  var DEMO_LINE_MS = 2600;
  var ORDER = { idle: -1, safe: 0, caution: 1, scam: 2 };

  var $ = function (id) { return document.getElementById(id); };

  var S = {
    status: { stt: false, ai: false, offline: false },
    running: false,
    source: 'demo',
    lines: [],
    spokenDigits: false,
    level: 'idle',
    score: 0,
    ruleFlags: [],
    ai: null,
    alerted: { caution: false, scam: false },
    startedAt: 0,
    timerId: null,
    demoTimer: null,
    audio: null,
    sttPending: 0,
    sttQueue: Promise.resolve(),
    sttWarned: false,
    aiInFlight: false,
    aiLast: 0,
    aiTimer: null,
    aiDirty: false,
    wakeLock: null,
    titleTimer: null
  };

  // ---------- helpers ----------
  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function highlight(text, phrases) {
    var lower = text.toLowerCase();
    var ranges = [];
    phrases.forEach(function (p) {
      if (!p || p === '••••') return;
      var q = p.toLowerCase(), i = 0;
      while ((i = lower.indexOf(q, i)) !== -1) { ranges.push([i, i + q.length]); i += q.length; }
    });
    ranges.sort(function (a, b) { return a[0] - b[0]; });
    var merged = [];
    ranges.forEach(function (r) {
      var last = merged[merged.length - 1];
      if (last && r[0] <= last[1]) last[1] = Math.max(last[1], r[1]); else merged.push(r.slice());
    });
    var out = '', pos = 0;
    merged.forEach(function (r) {
      out += esc(text.slice(pos, r[0])) + '<mark>' + esc(text.slice(r[0], r[1])) + '</mark>';
      pos = r[1];
    });
    return out + esc(text.slice(pos));
  }

  function clock(ms) {
    var s = Math.floor(ms / 1000);
    return String(Math.floor(s / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0');
  }

  function showError(msg) {
    $('error').textContent = msg;
    $('error').hidden = !msg;
  }

  function transcriptText() {
    return S.lines.map(function (l) { return l.text; }).join(' ');
  }

  // ---------- service status ----------
  function loadStatus() {
    return fetch('/api/status', { cache: 'no-store' })
      .then(function (r) { if (!r.ok) throw new Error(); return r.json(); })
      .then(function (j) { S.status = { stt: !!j.stt, ai: !!j.ai, sttModel: j.sttModel, aiModel: j.aiModel, offline: false }; })
      .catch(function () { S.status = { stt: false, ai: false, offline: true }; })
      .then(renderServices);
  }

  function renderServices() {
    var st = S.status;
    $('svc-stt').dataset.on = String(st.stt);
    $('svc-stt').textContent = 'Speech-to-text: ' + (st.stt ? 'Sarvam ' + (st.sttModel || '') : 'off');
    $('svc-ai').dataset.on = String(st.ai);
    $('svc-ai').textContent = 'AI check: ' + (st.ai ? 'OpenAI ' + (st.aiModel || '') : 'off');
    ['src-mic', 'src-tab', 'src-file'].forEach(function (id) {
      var input = $(id);
      input.disabled = !st.stt;
      input.parentNode.title = st.stt ? '' : (st.offline ? 'Start the server (npm start) to use live audio.' : 'Add SARVAM_API_KEY to .env to use live audio.');
    });
  }

  // ---------- risk ----------
  function levelFromAi(ai) {
    if (!ai) return 'safe';
    return ai.verdict === 'scam' ? 'scam' : ai.verdict === 'suspicious' ? 'caution' : 'safe';
  }

  function maxLevel(a, b) { return ORDER[a] >= ORDER[b] ? a : b; }

  // Risk only goes up during a call: once a scammer has asked for an OTP, later
  // small talk does not make the call safe again.
  function evaluate() {
    var r = Rules.analyze(transcriptText(), { spokenDigits: S.spokenDigits });
    S.ruleFlags = r.flags;
    var level = maxLevel(r.level, levelFromAi(S.ai));
    S.level = S.lines.length ? maxLevel(S.level === 'idle' ? 'safe' : S.level, level) : (S.running ? 'safe' : 'idle');
    S.score = Math.max(S.score, r.score, S.ai ? S.ai.score : 0);
    if (S.level === 'scam') S.score = Math.max(S.score, Rules.SCAM_AT);
    render();
    maybeAlert();
  }

  // ---------- rendering ----------
  var COPY = {
    idle: { tag: 'Not listening', title: 'Ready when your call starts', sub: 'Pick how to listen, then press Start.', hi: 'कॉल शुरू होते ही Start दबाएँ।' },
    safe: { tag: 'Listening', title: 'No warning signs yet', sub: 'Keep this page open. You will be warned the moment something sounds wrong.', hi: 'हम सुन रहे हैं। कुछ गलत लगा तो तुरंत बताएँगे।' },
    caution: { tag: 'Be careful', title: 'Be careful on this call', sub: 'Do not share any OTP, PIN or card details. Say you will call back on the official number.', hi: 'सावधान रहें। OTP, PIN या कार्ड की जानकारी न दें।' },
    scam: { tag: 'Scam call', title: 'Scam call. Hang up now.', sub: 'Do not share OTP, card number, CVV or PIN. Do not send money.', hi: 'यह धोखाधड़ी कॉल है। फोन काट दें।' }
  };

  function render() {
    var c = COPY[S.level];
    var st = $('status');
    st.dataset.level = S.level;
    st.dataset.live = String(S.running);
    $('state-tag').textContent = S.running ? c.tag : (S.level === 'idle' ? c.tag : 'Call ended · ' + c.tag);
    $('state-title').textContent = c.title;
    $('state-sub').textContent = c.sub;
    $('state-sub-hi').textContent = c.hi;
    $('pin').style.left = S.score + '%';
    $('score').textContent = S.score + '/100';

    var allFlags = S.ruleFlags.slice();
    var quotes = allFlags.map(function (f) { return f.quote; });
    if (S.ai) S.ai.redFlags.forEach(function (f) { quotes.push(f.quote); });

    // transcript
    var tr = $('transcript');
    if (!S.lines.length) {
      tr.innerHTML = '<li class="empty">The call\'s words will appear here as they are heard.</li>';
    } else {
      tr.innerHTML = S.lines.map(function (l) {
        return '<li data-who="' + esc(l.who) + '"><span class="who">' + esc(l.who) + '<time>' + l.at + '</time></span><span class="txt">' + highlight(l.text, quotes) + '</span></li>';
      }).join('');
      tr.scrollTop = tr.scrollHeight;
    }

    // AI verdict
    var box = $('ai-box');
    if (S.ai) {
      box.hidden = false;
      box.innerHTML =
        '<span class="eyebrow">AI check · ' + esc(S.ai.verdict) + ' · ' + S.ai.score + '/100' + (S.ai.scamType ? ' · ' + esc(S.ai.scamType) : '') + '</span>' +
        (S.ai.adviceEn ? '<span>' + esc(S.ai.adviceEn) + '</span>' : '') +
        (S.ai.adviceHi ? '<span class="hi" lang="hi">' + esc(S.ai.adviceHi) + '</span>' : '') +
        (S.ai.sayThis ? '<span class="say">Say: "' + esc(S.ai.sayThis) + '"</span>' : '');
    } else if (S.running && !S.status.ai) {
      box.hidden = false;
      box.innerHTML = '<span class="eyebrow">AI check off</span><span>Using the instant keyword detector only. Add OPENAI_API_KEY to .env for a smarter second opinion.</span>';
    } else {
      box.hidden = true;
    }

    // flags
    var items = allFlags.map(function (f) {
      return '<li class="flag" data-sev="' + f.severity + '">' +
        '<div class="flag-head"><h3>' + esc(f.label) + '</h3><span class="pills"><span class="pill" data-sev="' + f.severity + '">' + f.severity + '</span></span></div>' +
        '<span class="hi" lang="hi">' + esc(f.labelHi) + '</span>' +
        (f.quote && f.quote !== '••••' ? '<span class="quote">heard: "' + esc(f.quote) + '"</span>' : '') +
        '<span class="why">' + esc(f.why) + '</span></li>';
    });
    if (S.ai) {
      var sev = S.ai.verdict === 'scam' ? 'critical' : S.ai.verdict === 'suspicious' ? 'high' : 'medium';
      S.ai.redFlags.forEach(function (f) {
        items.push('<li class="flag" data-sev="' + sev + '"><div class="flag-head"><h3>' + esc(f.label) + '</h3><span class="pills"><span class="pill src-ai">AI</span></span></div>' +
          (f.quote ? '<span class="quote">heard: "' + esc(f.quote) + '"</span>' : '') + '</li>');
      });
    }
    $('flags').innerHTML = items.length ? items.join('') : '<li class="empty">No warning signs yet.</li>';
  }

  // ---------- alerts ----------
  function beep(pattern) {
    var ctx = S.audio && S.audio.ctx;
    try {
      if (!ctx || ctx.state === 'closed') { ctx = new (window.AudioContext || window.webkitAudioContext)(); }
      var t = ctx.currentTime;
      pattern.forEach(function (freq, i) {
        var o = ctx.createOscillator(), g = ctx.createGain();
        o.type = 'square'; o.frequency.value = freq;
        g.gain.setValueAtTime(0.0001, t + i * 0.28);
        g.gain.exponentialRampToValueAtTime(0.25, t + i * 0.28 + 0.02);
        g.gain.exponentialRampToValueAtTime(0.0001, t + i * 0.28 + 0.24);
        o.connect(g); g.connect(ctx.destination);
        o.start(t + i * 0.28); o.stop(t + i * 0.28 + 0.26);
      });
    } catch (e) { /* audio not available */ }
  }

  function speak(parts) {
    if (!$('opt-voice').checked || !('speechSynthesis' in window)) return;
    window.speechSynthesis.cancel();
    var voices = window.speechSynthesis.getVoices();
    parts.forEach(function (p) {
      var u = new SpeechSynthesisUtterance(p.text);
      u.lang = p.lang;
      var v = voices.find(function (x) { return x.lang && x.lang.toLowerCase().indexOf(p.lang.slice(0, 2)) === 0; });
      if (v) u.voice = v;
      u.rate = 1;
      window.speechSynthesis.speak(u);
    });
  }

  function notify(title, body, urgent) {
    if (!$('opt-notify').checked || !('Notification' in window) || Notification.permission !== 'granted') return;
    if (!document.hidden && !urgent) return;
    try {
      var n = new Notification(title, { body: body, tag: 'ruko-call-guard', requireInteraction: !!urgent });
      n.onclick = function () { window.focus(); n.close(); };
    } catch (e) { /* some browsers only allow notifications from a service worker */ }
  }

  function flashTitle(on) {
    clearInterval(S.titleTimer);
    document.title = 'Ruko Call Guard';
    if (!on) return;
    var alt = false;
    S.titleTimer = setInterval(function () {
      alt = !alt;
      document.title = alt ? '⚠ SCAM CALL: HANG UP' : 'Ruko Call Guard';
    }, 900);
  }

  function topReasons() {
    var labels = S.ruleFlags.map(function (f) { return f.label; });
    if (S.ai) S.ai.redFlags.forEach(function (f) { if (labels.indexOf(f.label) === -1) labels.push(f.label); });
    return labels.slice(0, 4);
  }

  function maybeAlert() {
    if (S.level === 'scam' && !S.alerted.scam) {
      S.alerted.scam = true;
      var reasons = topReasons();
      $('alarm-type').textContent = (S.ai && S.ai.scamType ? S.ai.scamType : 'Scam call detected');
      $('alarm-reasons').innerHTML = reasons.map(function (r) { return '<li>' + esc(r) + '</li>'; }).join('');
      if (S.ai && S.ai.sayThis) $('alarm-say').textContent = '"' + S.ai.sayThis + '"';
      $('alarm-warn').hidden = false;
      $('alarm-after').hidden = true;
      $('alarm').hidden = false;
      $('hung-up').focus();
      beep([880, 660, 880, 660, 880]);
      if (navigator.vibrate) navigator.vibrate([400, 150, 400, 150, 400]);
      speak([
        { text: 'Warning. This looks like a scam call. Hang up now. Do not share any OTP, card or PIN.', lang: 'en-IN' },
        { text: 'सावधान। यह धोखाधड़ी कॉल है। फोन काट दें। ओटीपी किसी को न बताएं।', lang: 'hi-IN' }
      ]);
      notify('Scam call: hang up now', reasons.join(' · ') || 'The caller is using scam tactics.', true);
      flashTitle(true);
    } else if (S.level === 'caution' && !S.alerted.caution && !S.alerted.scam) {
      S.alerted.caution = true;
      beep([660, 660]);
      if (navigator.vibrate) navigator.vibrate([200, 100, 200]);
      speak([{ text: 'Be careful. Do not share any OTP or card details on this call.', lang: 'en-IN' }]);
      notify('Be careful on this call', topReasons().join(' · '), false);
    }
  }

  function closeAlarm() {
    $('alarm').hidden = true;
    flashTitle(false);
    if ('speechSynthesis' in window) window.speechSynthesis.cancel();
  }

  // ---------- transcript intake ----------
  function addLine(who, text) {
    var masked = Rules.maskNumbers(text);
    if (!masked.text.trim()) return;
    if (masked.spokenDigits) S.spokenDigits = true;
    S.lines.push({ who: who, text: masked.text.trim(), at: clock(Date.now() - S.startedAt) });
    evaluate();
    scheduleAi();
  }

  // ---------- AI ----------
  function scheduleAi() {
    if (!S.status.ai) return;
    S.aiDirty = true;
    if (S.aiInFlight || S.aiTimer) return;
    var wait = Math.max(0, AI_MIN_GAP_MS - (Date.now() - S.aiLast));
    S.aiTimer = setTimeout(runAi, wait);
  }

  function runAi() {
    S.aiTimer = null;
    if (!S.aiDirty || !S.lines.length) return;
    S.aiDirty = false;
    S.aiInFlight = true;
    S.aiLast = Date.now();
    var session = S.startedAt;
    fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ transcript: transcriptText() })
    })
      .then(function (r) { return r.json().then(function (j) { if (!r.ok) throw new Error(j.error || 'AI check failed.'); return j; }); })
      .then(function (j) {
        if (session !== S.startedAt) return; // a newer call has started
        if (j.ai) {
          // Keep the highest AI verdict seen during this call.
          if (!S.ai || j.score >= S.ai.score) S.ai = j;
          evaluate();
        }
      })
      .catch(function (e) { showError(e.message); })
      .then(function () {
        S.aiInFlight = false;
        if (S.aiDirty) scheduleAi();
      });
  }

  // ---------- audio capture ----------
  function downsample(data, fromRate) {
    if (fromRate === TARGET_RATE) return data;
    var ratio = fromRate / TARGET_RATE;
    var out = new Float32Array(Math.floor(data.length / ratio));
    for (var i = 0; i < out.length; i++) {
      var start = Math.floor(i * ratio), end = Math.min(data.length, Math.floor((i + 1) * ratio));
      var sum = 0;
      for (var j = start; j < end; j++) sum += data[j];
      out[i] = sum / Math.max(1, end - start);
    }
    return out;
  }

  function encodeWav(samples) {
    var buffer = new ArrayBuffer(44 + samples.length * 2);
    var v = new DataView(buffer);
    function str(o, s) { for (var i = 0; i < s.length; i++) v.setUint8(o + i, s.charCodeAt(i)); }
    str(0, 'RIFF'); v.setUint32(4, 36 + samples.length * 2, true); str(8, 'WAVE');
    str(12, 'fmt '); v.setUint32(16, 16, true); v.setUint16(20, 1, true); v.setUint16(22, 1, true);
    v.setUint32(24, TARGET_RATE, true); v.setUint32(28, TARGET_RATE * 2, true); v.setUint16(32, 2, true); v.setUint16(34, 16, true);
    str(36, 'data'); v.setUint32(40, samples.length * 2, true);
    for (var i = 0, o = 44; i < samples.length; i++, o += 2) {
      var s = Math.max(-1, Math.min(1, samples[i]));
      v.setInt16(o, s < 0 ? s * 0x8000 : s * 0x7fff, true);
    }
    return new Blob([buffer], { type: 'audio/wav' });
  }

  function rms(data) {
    var sum = 0;
    for (var i = 0; i < data.length; i++) sum += data[i] * data[i];
    return Math.sqrt(sum / Math.max(1, data.length));
  }

  function onSamples(chunk) {
    var a = S.audio;
    if (!a) return;
    var level = rms(chunk);
    $('level-fill').style.width = Math.min(100, level * 600) + '%';
    a.parts.push(chunk);
    a.count += chunk.length;
    if (a.count >= a.ctx.sampleRate * CHUNK_SECONDS) flushChunk();
  }

  function flushChunk() {
    var a = S.audio;
    if (!a || !a.count) return;
    var all = new Float32Array(a.count), o = 0;
    a.parts.forEach(function (p) { all.set(p, o); o += p.length; });
    a.parts = []; a.count = 0;
    var pcm = downsample(all, a.ctx.sampleRate);
    if (rms(pcm) < SILENCE_RMS) { $('hearing-label').textContent = 'Quiet'; return; }
    $('hearing-label').textContent = 'Hearing';
    sendToStt(encodeWav(pcm));
  }

  function renderPending() {
    $('pending').textContent = S.sttPending ? 'transcribing ' + S.sttPending + '…' : '';
  }

  function sendToStt(wav) {
    if (!S.status.stt) {
      if (!S.sttWarned) { S.sttWarned = true; showError('Speech-to-text is off. Add SARVAM_API_KEY to call-guard/.env and restart the server.'); }
      return;
    }
    if (S.sttPending >= MAX_PENDING_STT) return; // network is slow; skip rather than lag behind the call
    S.sttPending++; renderPending();
    var session = S.startedAt;
    S.sttQueue = S.sttQueue
      .then(function () {
        return fetch('/api/stt', { method: 'POST', headers: { 'Content-Type': 'audio/wav' }, body: wav });
      })
      .then(function (r) { return r.json().then(function (j) { if (!r.ok) throw new Error(j.error || 'Speech-to-text failed.'); return j; }); })
      .then(function (j) { if (session === S.startedAt && j.text) { showError(''); addLine('Call', j.text); } })
      .catch(function (e) { showError(e.message); })
      .then(function () { S.sttPending--; renderPending(); });
  }

  function startAudio(streams, fileBuffer) {
    var ctx = new (window.AudioContext || window.webkitAudioContext)();
    return ctx.audioWorklet.addModule('tapWorklet.js').then(function () {
      var tap = new AudioWorkletNode(ctx, 'ruko-tap');
      var mute = ctx.createGain(); mute.gain.value = 0;
      tap.connect(mute); mute.connect(ctx.destination);
      S.audio = { ctx: ctx, tap: tap, streams: streams, parts: [], count: 0, fileSource: null };
      tap.port.onmessage = function (e) { onSamples(e.data); };
      streams.forEach(function (s) {
        if (s.getAudioTracks().length) ctx.createMediaStreamSource(s).connect(tap);
        s.getTracks().forEach(function (t) { t.addEventListener('ended', function () { if (S.running && S.source === 'tab' && t.kind === 'audio') stop(); }); });
      });
      if (fileBuffer) {
        return ctx.decodeAudioData(fileBuffer).then(function (decoded) {
          var src = ctx.createBufferSource();
          src.buffer = decoded;
          src.connect(tap);
          src.connect(ctx.destination); // you hear the recording while it is checked
          src.onended = function () { if (S.running) { flushChunk(); stop(); } };
          S.audio.fileSource = src;
          src.start();
        });
      }
    });
  }

  function stopAudio() {
    var a = S.audio;
    if (!a) return;
    S.audio = null;
    if (a.parts.length && S.source !== 'file') {
      // send whatever was left of the last chunk
      S.audio = a; flushChunk(); S.audio = null;
    }
    try { if (a.fileSource) a.fileSource.stop(); } catch (e) { /* already stopped */ }
    a.streams.forEach(function (s) { s.getTracks().forEach(function (t) { t.stop(); }); });
    try { a.tap.port.onmessage = null; a.ctx.close(); } catch (e) { /* closed */ }
    $('level-fill').style.width = '0%';
  }

  // ---------- demo ----------
  function runDemo(call) {
    var i = 0;
    function next() {
      if (!S.running) return;
      if (i >= call.lines.length) { S.demoTimer = setTimeout(stop, 1500); return; }
      var line = call.lines[i++];
      addLine(line[0], line[1]);
      S.demoTimer = setTimeout(next, DEMO_LINE_MS);
    }
    S.demoTimer = setTimeout(next, 600);
  }

  function keepWakeLock(lock) {
    S.wakeLock = lock;
    lock.addEventListener('release', function () { if (S.wakeLock === lock) S.wakeLock = null; });
  }

  // ---------- session ----------
  function reset() {
    S.lines = []; S.spokenDigits = false; S.level = 'safe'; S.score = 0; S.ruleFlags = []; S.ai = null;
    S.alerted = { caution: false, scam: false }; S.sttWarned = false; S.aiDirty = false;
    clearTimeout(S.aiTimer); S.aiTimer = null;
    showError('');
  }

  function start() {
    if (S.running) return stop();
    var source = document.querySelector('input[name="source"]:checked').value;
    if (source !== 'demo' && !window.isSecureContext) {
      showError('The microphone only works on https:// or http://localhost. Open the app from the server address.');
      return;
    }
    if (source === 'file' && !$('audio-file').files[0]) { showError('Choose an audio file first.'); return; }

    S.source = source;
    reset();
    S.startedAt = Date.now();

    if ($('opt-notify').checked && 'Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission().catch(function () {});
    }
    if (navigator.wakeLock) navigator.wakeLock.request('screen').then(keepWakeLock).catch(function () {});
    if ('speechSynthesis' in window) window.speechSynthesis.getVoices();

    var ready;
    if (source === 'demo') {
      var call = DEMO.find(function (c) { return c.id === $('demo-call').value; }) || DEMO[0];
      ready = Promise.resolve().then(function () { runDemo(call); });
    } else if (source === 'mic') {
      ready = navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: false, noiseSuppression: true, autoGainControl: true } })
        .then(function (mic) { return startAudio([mic]); });
    } else if (source === 'tab') {
      ready = navigator.mediaDevices.getDisplayMedia({ video: true, audio: true })
        .then(function (display) {
          if (!display.getAudioTracks().length) {
            display.getTracks().forEach(function (t) { t.stop(); });
            throw new Error('No tab audio was shared. Start again and turn on "Share tab audio".');
          }
          return navigator.mediaDevices.getUserMedia({ audio: true })
            .then(function (mic) { return [display, mic]; }, function () { return [display]; });
        })
        .then(function (streams) { return startAudio(streams); });
    } else {
      ready = $('audio-file').files[0].arrayBuffer().then(function (buf) { return startAudio([], buf); });
    }

    S.running = true;
    $('start').textContent = 'Stop';
    $('start').classList.add('stop');
    $('hearing').hidden = source === 'demo';
    setControlsDisabled(true);
    S.timerId = setInterval(function () { $('timer').textContent = clock(Date.now() - S.startedAt); }, 500);
    render();

    ready.catch(function (e) {
      var msg = e && e.name === 'NotAllowedError' ? 'Permission was refused. Allow microphone or screen sharing access and try again.' : (e && e.message) || 'Could not start listening.';
      stop();
      showError(msg);
    });
  }

  function stop() {
    if (!S.running) return;
    S.running = false;
    clearTimeout(S.demoTimer);
    clearInterval(S.timerId);
    stopAudio();
    if (S.wakeLock) { S.wakeLock.release().catch(function () {}); S.wakeLock = null; }
    $('start').textContent = 'Start listening';
    $('start').classList.remove('stop');
    $('hearing').hidden = true;
    setControlsDisabled(false);
    if (!S.lines.length) S.level = 'idle';
    render();
  }

  function setControlsDisabled(on) {
    document.querySelectorAll('input[name="source"], #demo-call, #audio-file').forEach(function (el) {
      if (on) el.disabled = true;
      else el.disabled = false;
    });
    if (!on) renderServices();
  }

  function syncSourceOptions() {
    var v = document.querySelector('input[name="source"]:checked').value;
    $('opt-demo').hidden = v !== 'demo';
    $('opt-file').hidden = v !== 'file';
    $('opt-mic').hidden = v !== 'mic';
    $('opt-tab').hidden = v !== 'tab';
  }

  // ---------- wire up ----------
  $('demo-call').innerHTML = DEMO.map(function (c) {
    return '<option value="' + c.id + '">' + esc(c.label) + (c.expected === 'safe' ? ' (normal)' : '') + '</option>';
  }).join('');
  document.querySelectorAll('input[name="source"]').forEach(function (r) { r.addEventListener('change', syncSourceOptions); });
  $('start').addEventListener('click', start);
  $('keep').addEventListener('click', closeAlarm);
  $('hung-up').addEventListener('click', function () {
    stop();
    $('alarm-warn').hidden = true;
    $('alarm-after').hidden = false;
    flashTitle(false);
    if ('speechSynthesis' in window) window.speechSynthesis.cancel();
    $('close-alarm').focus();
  });
  $('close-alarm').addEventListener('click', closeAlarm);
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && !$('alarm').hidden) closeAlarm(); });
  document.addEventListener('visibilitychange', function () {
    // Wake locks are released when the tab is hidden; take it again on return.
    if (!document.hidden && S.running && navigator.wakeLock && !S.wakeLock) {
      navigator.wakeLock.request('screen').then(keepWakeLock).catch(function () {});
    }
  });

  syncSourceOptions();
  render();
  loadStatus().then(function () {
    if (S.status.stt) { $('src-mic').checked = true; syncSourceOptions(); }
  });

  // Exposed for automated tests only.
  window.__rukoCallGuard = { state: S, addLine: addLine, encodeWav: encodeWav, downsample: downsample };
})();
