/* Ruko Call Guard: browser app. Everything runs on this device:
 *   audio -> Vosk speech recognition (WebAssembly, offline) -> text
 *   text  -> FraudRules (rule-based) -> safe / caution / scam + fraud type
 * No audio or text is sent to any server. */
(function () {
  'use strict';

  var Rules = window.FraudRules;
  var DEMO = window.DemoCalls;

  var MODEL_FILES = { hi: 'models/hi.tar.gz', 'en-in': 'models/en-in.tar.gz' };
  var MODEL_NAMES = { hi: 'Hindi', 'en-in': 'English (India)' };
  var MODEL_LOAD_TIMEOUT_MS = 180000; // first load downloads ~40 MB; later loads come from browser storage
  var PARTIAL_CHECK_MS = 300;         // check half-heard words at most this often
  var DEMO_LINE_MS = 2600;
  var ORDER = { idle: -1, safe: 0, caution: 1, scam: 2 };

  var $ = function (id) { return document.getElementById(id); };

  var S = {
    models: { hi: false, 'en-in': false },
    voskLoaded: null,     // Promise for the vosk.js script
    voskModels: {},       // lang -> Promise<Model>, kept across calls so models load once
    running: false,
    source: 'demo',
    lines: [],
    partials: {},         // lang -> text being heard right now
    spokenDigits: false,
    level: 'idle',
    score: 0,
    flags: {},            // id -> flag, everything seen during this call
    fraudType: null,
    isUpiFraud: false,
    alerted: { caution: false, scam: false },
    startedAt: 0,
    timerId: null,
    demoTimer: null,
    partialTimer: null,
    lastPartialCheck: 0,
    audio: null,
    recognizers: [],
    wakeLock: null,
    titleTimer: null
  };

  // ---------- helpers ----------
  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function clock(ms) {
    var s = Math.floor(ms / 1000);
    return String(Math.floor(s / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0');
  }

  function showError(msg) {
    $('error').textContent = msg;
    $('error').hidden = !msg;
  }

  function withTimeout(promise, ms, message) {
    return new Promise(function (resolve, reject) {
      var t = setTimeout(function () { reject(new Error(message)); }, ms);
      promise.then(function (v) { clearTimeout(t); resolve(v); }, function (e) { clearTimeout(t); reject(e); });
    });
  }

  // Highlight the exact phrases the rules matched. Rule quotes are in
  // normalized form (e.g. Hindi words mapped to Roman), so each transcript word
  // is normalized the same way before comparing whole phrases.
  function highlight(text, quotes) {
    var parts = text.split(/(\s+)/);
    var words = [];
    parts.forEach(function (part, i) {
      if (/\S/.test(part)) words.push({ i: i, toks: Rules.tokenize(part).filter(function (t) { return t !== '|'; }) });
    });
    var marked = {};
    quotes.forEach(function (q) {
      var want = String(q || '').split(' ').filter(Boolean);
      if (!want.length || q === '••••') return;
      for (var w = 0; w < words.length; w++) {
        var k = 0, end = w;
        while (end < words.length && k < want.length) {
          var toks = words[end].toks;
          var ok = toks.length > 0;
          for (var t = 0; t < toks.length && k < want.length; t++, k++) { if (toks[t] !== want[k]) { ok = false; break; } }
          if (!ok) break;
          end++;
        }
        if (k === want.length) { for (var m = w; m < end; m++) marked[words[m].i] = true; }
      }
    });
    return parts.map(function (part, i) { return marked[i] ? '<mark>' + esc(part) + '</mark>' : esc(part); }).join('');
  }

  // ---------- speech models ----------
  function detectModels() {
    return fetch('models/index.json', { cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : []; }, function () { return []; })
      .then(function (list) {
        Object.keys(MODEL_FILES).forEach(function (lang) { S.models[lang] = list.indexOf(lang) !== -1; });
        renderSpeechStatus();
      });
  }

  function renderSpeechStatus() {
    var have = Object.keys(S.models).filter(function (l) { return S.models[l]; });
    var chip = $('svc-speech');
    chip.dataset.on = String(have.length > 0);
    chip.textContent = have.length
      ? 'Speech: on-device (' + have.map(function (l) { return MODEL_NAMES[l]; }).join(', ') + ')'
      : 'Speech: no model yet';
    ['src-mic', 'src-tab', 'src-file'].forEach(function (id) {
      $(id).disabled = S.running || !have.length;
    });
    var sel = $('speech-lang');
    Array.prototype.forEach.call(sel.options, function (o) {
      o.disabled = o.value === 'both' ? !(S.models.hi && S.models['en-in']) : !S.models[o.value];
    });
    if (sel.selectedOptions[0] && sel.selectedOptions[0].disabled) {
      var first = Array.prototype.find.call(sel.options, function (o) { return !o.disabled; });
      if (first) sel.value = first.value;
    }
    var note = $('model-note');
    if (!have.length) {
      note.hidden = false;
      note.innerHTML = 'Live listening needs a free offline speech model (one-time, about 40 MB). Run <b>npm run models</b> and reload. Demo calls and typed tests work now.';
    } else {
      note.hidden = true;
    }
  }

  function loadVoskScript() {
    if (S.voskLoaded) return S.voskLoaded;
    S.voskLoaded = new Promise(function (resolve, reject) {
      var s = document.createElement('script');
      s.src = 'vendor/vosk.js';
      s.onload = function () { window.Vosk ? resolve(window.Vosk) : reject(new Error('Speech engine did not load.')); };
      s.onerror = function () { S.voskLoaded = null; reject(new Error('Speech engine is missing. Run npm install, then restart the server.')); };
      document.head.appendChild(s);
    });
    return S.voskLoaded;
  }

  function loadModel(lang) {
    if (S.voskModels[lang]) return S.voskModels[lang];
    var url = new URL(MODEL_FILES[lang], location.href).href;
    var p = loadVoskScript().then(function (Vosk) {
      return withTimeout(Vosk.createModel(url, -1), MODEL_LOAD_TIMEOUT_MS,
        'The ' + MODEL_NAMES[lang] + ' speech model took too long to load. Reload the page and try again.');
    });
    p.catch(function () { delete S.voskModels[lang]; });
    S.voskModels[lang] = p;
    return p;
  }

  function selectedLangs() {
    var v = $('speech-lang').value;
    return v === 'both' ? ['hi', 'en-in'] : [v];
  }

  // ---------- risk ----------
  // Risk only goes up during a call: once a caller has asked for an OTP, later
  // small talk does not make the call safe again.
  function evaluate() {
    var utterances = S.lines.map(function (l) { return l.text; });
    Object.keys(S.partials).forEach(function (k) { if (S.partials[k]) utterances.push(S.partials[k]); });
    var r = Rules.analyze(utterances, { spokenDigits: S.spokenDigits });

    r.flags.forEach(function (f) { if (!S.flags[f.id]) S.flags[f.id] = f; });
    if (r.fraudType && (!S.fraudType || ORDER[r.level] >= ORDER[S.level])) S.fraudType = r.fraudType;
    S.isUpiFraud = S.isUpiFraud || r.isUpiFraud;

    var base = S.level === 'idle' ? 'safe' : S.level;
    S.level = ORDER[r.level] > ORDER[base] ? r.level : base;
    S.score = Math.max(S.score, r.score);
    render();
    maybeAlert();
  }

  function sortedFlags() {
    var order = { critical: 0, high: 1, medium: 2 };
    return Object.keys(S.flags).map(function (k) { return S.flags[k]; })
      .sort(function (a, b) { return order[a.severity] - order[b.severity]; });
  }

  // ---------- rendering ----------
  var COPY = {
    idle: { tag: 'Not listening', title: 'Ready when your call starts', sub: 'Pick how to listen, then press Start.', hi: 'कॉल शुरू होते ही Start दबाएँ।' },
    safe: { tag: 'Listening', title: 'No warning signs yet', sub: 'Keep this page open. You will be warned the moment something sounds wrong.', hi: 'हम सुन रहे हैं। कुछ गलत लगा तो तुरंत बताएँगे।' },
    caution: { tag: 'Be careful', title: 'Be careful on this call', sub: 'Do not share any OTP, PIN or card details, and do not scan or approve anything.', hi: 'सावधान रहें। OTP, PIN या कार्ड की जानकारी न दें।' },
    scam: { tag: 'Fraud call', title: 'Fraud call. Hang up now.', sub: 'Do not share OTP, card number, CVV or PIN. Do not send money or scan anything.', hi: 'यह धोखाधड़ी कॉल है। फोन काट दें।' }
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

    var showVerdict = S.level === 'caution' || S.level === 'scam';
    $('verdict-row').hidden = !showVerdict;
    if (showVerdict) {
      $('type-pill').textContent = S.fraudType ? S.fraudType.label + ' · ' + S.fraudType.labelHi : 'Suspicious call';
      $('upi-pill').dataset.upi = String(S.isUpiFraud);
      $('upi-pill').textContent = 'UPI fraud: ' + (S.isUpiFraud ? 'Yes' : 'No');
    }

    var flags = sortedFlags();
    var quotes = flags.map(function (f) { return f.quote; });

    // transcript, plus what is being heard right now
    var items = S.lines.map(function (l) {
      return '<li data-who="' + esc(l.who) + '"><span class="who">' + esc(l.who) + '<time>' + l.at + '</time></span><span class="txt">' + highlight(l.text, quotes) + '</span></li>';
    });
    Object.keys(S.partials).forEach(function (k) {
      if (S.partials[k]) items.push('<li class="partial"><span class="who">Hearing</span><span class="txt">' + highlight(S.partials[k], quotes) + '…</span></li>');
    });
    var tr = $('transcript');
    tr.innerHTML = items.length ? items.join('') : '<li class="empty">The call\'s words will appear here as they are heard.</li>';
    tr.scrollTop = tr.scrollHeight;

    // advice for the detected fraud type
    var adv = $('advice');
    if (showVerdict && S.fraudType) {
      adv.hidden = false;
      adv.innerHTML = '<span class="eyebrow">' + esc(S.fraudType.label) + ': what to do</span><span>' + esc(S.fraudType.adviceEn) + '</span><span class="hi" lang="hi">' + esc(S.fraudType.adviceHi) + '</span>';
    } else {
      adv.hidden = true;
    }

    $('flags').innerHTML = flags.length ? flags.map(function (f) {
      return '<li class="flag" data-sev="' + f.severity + '">' +
        '<div class="flag-head"><h3>' + esc(f.label) + '</h3><span class="pills"><span class="pill" data-sev="' + f.severity + '">' + f.severity + '</span></span></div>' +
        '<span class="hi" lang="hi">' + esc(f.labelHi) + '</span>' +
        (f.quote && f.quote !== '••••' ? '<span class="quote">heard: "' + esc(f.quote) + '"</span>' : '') +
        '<span class="why">' + esc(f.why) + '</span></li>';
    }).join('') : '<li class="empty">No warning signs yet.</li>';
  }

  // ---------- alerts ----------
  var beepCtx = null;
  function beep(pattern) {
    try {
      var ctx = S.audio && S.audio.ctx.state !== 'closed' ? S.audio.ctx : (beepCtx || (beepCtx = new (window.AudioContext || window.webkitAudioContext)()));
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
      document.title = alt ? '⚠ FRAUD CALL: HANG UP' : 'Ruko Call Guard';
    }, 900);
  }

  function maybeAlert() {
    var type = S.fraudType;
    if (S.level === 'scam' && !S.alerted.scam) {
      S.alerted.scam = true;
      var reasons = sortedFlags().slice(0, 4).map(function (f) { return f.label; });
      $('alarm-type').textContent = (type ? type.label : 'Fraud call') + (S.isUpiFraud && (!type || type.id !== 'upi_fraud') ? ' · UPI fraud' : '') + ' detected';
      $('alarm-reasons').innerHTML = reasons.map(function (r) { return '<li>' + esc(r) + '</li>'; }).join('');
      $('alarm-advice').textContent = type ? type.adviceEn : 'Do not share any OTP, card number, CVV or PIN. Do not send money.';
      $('alarm-advice-hi').textContent = type ? type.adviceHi : 'OTP, कार्ड नंबर या PIN किसी को न बताएं।';
      $('alarm-warn').hidden = false;
      $('alarm-after').hidden = true;
      $('alarm').hidden = false;
      $('hung-up').focus();
      beep([880, 660, 880, 660, 880]);
      if (navigator.vibrate) navigator.vibrate([400, 150, 400, 150, 400]);
      speak([
        { text: 'Warning. This is a fraud call. Hang up now. ' + (type ? type.adviceEn : ''), lang: 'en-IN' },
        { text: 'सावधान। यह धोखाधड़ी कॉल है। फोन काट दें।', lang: 'hi-IN' }
      ]);
      notify('Fraud call: hang up now', (type ? type.label + ': ' : '') + reasons.join(' · '), true);
      flashTitle(true);
    } else if (S.level === 'caution' && !S.alerted.caution && !S.alerted.scam) {
      S.alerted.caution = true;
      beep([660, 660]);
      if (navigator.vibrate) navigator.vibrate([200, 100, 200]);
      speak([{ text: 'Be careful. Do not share any OTP, PIN or card details on this call.', lang: 'en-IN' }]);
      notify('Be careful on this call', sortedFlags().map(function (f) { return f.label; }).join(' · '), false);
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
  }

  // Checking half-heard words gives a warning before the sentence ends. Vosk
  // repeats the same partial many times a second (often empty during silence),
  // so only changed text is checked, and at most once per PARTIAL_CHECK_MS.
  function setPartial(lang, text) {
    var masked = Rules.maskNumbers(text || '');
    var clean = masked.text.trim();
    if (clean === (S.partials[lang] || '')) return;
    if (masked.spokenDigits) S.spokenDigits = true;
    S.partials[lang] = clean;
    var wait = PARTIAL_CHECK_MS - (Date.now() - S.lastPartialCheck);
    if (wait <= 0) { checkPartials(); return; }
    if (!S.partialTimer) S.partialTimer = setTimeout(checkPartials, wait);
  }

  function checkPartials() {
    clearTimeout(S.partialTimer);
    S.partialTimer = null;
    S.lastPartialCheck = Date.now();
    if (S.running) evaluate();
  }

  // ---------- audio capture ----------
  function makeContext() {
    var AC = window.AudioContext || window.webkitAudioContext;
    try { return new AC({ sampleRate: 16000 }); } catch (e) { return new AC(); } // 16 kHz is what the models use
  }

  function rms(data) {
    var sum = 0;
    for (var i = 0; i < data.length; i++) sum += data[i] * data[i];
    return Math.sqrt(sum / Math.max(1, data.length));
  }

  function startAudio(streams, fileBuffer) {
    var langs = selectedLangs();
    $('speech-state').textContent = 'Loading speech model…';
    return Promise.all(langs.map(loadModel)).then(function (models) {
      if (!S.running) { streams.forEach(function (st) { st.getTracks().forEach(function (t) { t.stop(); }); }); return; }
      var ctx = makeContext();
      S.audio = { ctx: ctx, tap: null, streams: streams, fileSource: null };
      S.recognizers = models.map(function (model, i) {
        var lang = langs[i];
        var rec = new model.KaldiRecognizer(ctx.sampleRate);
        rec.on('partialresult', function (m) { if (S.running) setPartial(lang, m.result.partial); });
        rec.on('result', function (m) {
          if (!S.running && !S.audio) return;
          S.partials[lang] = '';
          var text = (m.result && m.result.text) || '';
          if (text.trim()) addLine(langs.length > 1 ? (lang === 'hi' ? 'हिंदी' : 'EN') : 'Call', text);
          else render();
        });
        return rec;
      });
      return ctx.audioWorklet.addModule('tapWorklet.js').then(function () {
        var tap = new AudioWorkletNode(ctx, 'ruko-tap');
        var mute = ctx.createGain(); mute.gain.value = 0;
        tap.connect(mute); mute.connect(ctx.destination);
        S.audio.tap = tap;
        tap.port.onmessage = function (e) {
          var chunk = e.data;
          $('level-fill').style.width = Math.min(100, rms(chunk) * 600) + '%';
          S.recognizers.forEach(function (rec) { rec.acceptWaveformFloat(chunk, ctx.sampleRate); });
        };
        streams.forEach(function (s) {
          if (s.getAudioTracks().length) ctx.createMediaStreamSource(s).connect(tap);
          s.getTracks().forEach(function (t) { t.addEventListener('ended', function () { if (S.running && t.kind === 'audio') stop(); }); });
        });
        $('speech-state').textContent = 'on-device · ' + langs.map(function (l) { return MODEL_NAMES[l]; }).join(' + ');
        if (fileBuffer) {
          return ctx.decodeAudioData(fileBuffer).then(function (decoded) {
            var src = ctx.createBufferSource();
            src.buffer = decoded;
            src.connect(tap);
            src.connect(ctx.destination); // you hear the recording while it is checked
            src.onended = function () { if (S.running) setTimeout(stop, 1200); };
            S.audio.fileSource = src;
            src.start();
          });
        }
      });
    });
  }

  function stopAudio() {
    var a = S.audio;
    S.recognizers.forEach(function (rec) { try { rec.retrieveFinalResult(); } catch (e) { /* ignore */ } });
    var recs = S.recognizers;
    S.recognizers = [];
    // give the last words a moment to arrive, then free the recognizers
    setTimeout(function () { recs.forEach(function (rec) { try { rec.remove(); } catch (e) { /* ignore */ } }); S.audio = null; }, 1500);
    if (!a) return;
    try { if (a.fileSource) a.fileSource.stop(); } catch (e) { /* already stopped */ }
    a.streams.forEach(function (s) { s.getTracks().forEach(function (t) { t.stop(); }); });
    try { if (a.tap) a.tap.port.onmessage = null; a.ctx.close(); } catch (e) { /* closed */ }
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

  // ---------- session ----------
  function reset() {
    S.lines = []; S.partials = {}; S.spokenDigits = false; S.level = 'safe'; S.score = 0; S.flags = {};
    S.fraudType = null; S.isUpiFraud = false; S.alerted = { caution: false, scam: false };
    showError('');
  }

  function begin(source) {
    S.source = source;
    reset();
    S.startedAt = Date.now();
    S.running = true;
    if ($('opt-notify').checked && 'Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission().catch(function () {});
    }
    if (navigator.wakeLock) navigator.wakeLock.request('screen').then(keepWakeLock).catch(function () {});
    if ('speechSynthesis' in window) window.speechSynthesis.getVoices();
    $('start').textContent = 'Stop';
    $('start').classList.add('stop');
    $('hearing').hidden = !(source === 'mic' || source === 'tab' || source === 'file');
    setControlsDisabled(true);
    S.timerId = setInterval(function () { $('timer').textContent = clock(Date.now() - S.startedAt); }, 500);
    render();
  }

  function start() {
    if (S.running) return stop();
    var source = document.querySelector('input[name="source"]:checked').value;
    var live = source === 'mic' || source === 'tab' || source === 'file';
    if (live && !window.isSecureContext) {
      showError('The microphone only works on https:// or http://localhost. Open the app from the server address.');
      return;
    }
    if (source === 'file' && !$('audio-file').files[0]) { showError('Choose an audio file first.'); return; }

    begin(source);

    var ready;
    if (source === 'demo') {
      var call = DEMO.find(function (c) { return c.id === $('demo-call').value; }) || DEMO[0];
      ready = Promise.resolve().then(function () { runDemo(call); });
    } else if (source === 'mic') {
      ready = navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: false, noiseSuppression: true, autoGainControl: true, channelCount: 1 } })
        .then(function (mic) { if (!S.running) { mic.getTracks().forEach(function (t) { t.stop(); }); return; } return startAudio([mic]); });
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
    clearTimeout(S.partialTimer); S.partialTimer = null;
    clearInterval(S.timerId);
    stopAudio();
    S.partials = {};
    if (S.wakeLock) { S.wakeLock.release().catch(function () {}); S.wakeLock = null; }
    $('start').textContent = 'Start listening';
    $('start').classList.remove('stop');
    $('hearing').hidden = true;
    $('speech-state').textContent = '';
    setControlsDisabled(false);
    if (!S.lines.length) S.level = 'idle';
    render();
  }

  function keepWakeLock(lock) {
    S.wakeLock = lock;
    lock.addEventListener('release', function () { if (S.wakeLock === lock) S.wakeLock = null; });
  }

  function setControlsDisabled(on) {
    document.querySelectorAll('input[name="source"], #demo-call, #audio-file, #speech-lang').forEach(function (el) { el.disabled = on; });
    if (!on) renderSpeechStatus();
  }

  function syncSourceOptions() {
    var v = document.querySelector('input[name="source"]:checked').value;
    $('opt-demo').hidden = v !== 'demo';
    $('opt-file').hidden = v !== 'file';
    $('opt-mic').hidden = v !== 'mic';
    $('opt-tab').hidden = v !== 'tab';
    $('opt-lang').hidden = v === 'demo';
  }

  // Typed sentences go through exactly the same checks and alarm as speech.
  function addTyped(e) {
    e.preventDefault();
    var text = $('type-text').value.trim();
    if (!text) return;
    if (!S.running) begin('text');
    addLine('Typed', text);
    $('type-text').value = '';
    $('type-text').focus();
  }

  // ---------- wire up ----------
  $('demo-call').innerHTML = DEMO.map(function (c) {
    return '<option value="' + c.id + '">' + esc(c.label) + (c.expected === 'safe' ? ' (normal)' : '') + '</option>';
  }).join('');
  document.querySelectorAll('input[name="source"]').forEach(function (r) { r.addEventListener('change', syncSourceOptions); });
  $('start').addEventListener('click', start);
  $('type-form').addEventListener('submit', addTyped);
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
  detectModels().then(function () {
    if (S.models.hi || S.models['en-in']) { $('src-mic').checked = true; syncSourceOptions(); }
  });

  // Exposed for automated tests only.
  window.__rukoCallGuard = { state: S, addLine: addLine, setPartial: setPartial, evaluate: evaluate };
})();
