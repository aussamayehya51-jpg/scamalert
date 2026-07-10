// ScamAlert — Layer 1: the offline brain.
// Runs 100% on the device, no internet, nothing leaves the phone. Catches the
// common, obvious scams instantly and privately. When it is unsure, the app can
// offer a "deep check" with the online AI (Layer 2).
// Works in the browser (window.ScamEngine) AND in Node (module.exports), so the
// exact same code that ships can be logic-tested.
(function (root) {
  'use strict';

  // Brands scammers impersonate most in Lebanon + globally.
  var BRANDS = [
    'whish', 'omt', 'bankaudi', 'blombank', 'blom', 'byblosbank', 'byblos',
    'fransabank', 'creditlibanais', 'bankofbeirut', 'sgbl', 'aramex', 'dhl',
    'fedex', 'ups', 'ogero', 'touch', 'alfa', 'microsoft', 'apple', 'icloud',
    'whatsapp', 'facebook', 'instagram', 'netflix', 'paypal', 'amazon',
    'westernunion', 'moneygram'
  ];
  var SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'cutt.ly', 'is.gd', 'ow.ly', 'rebrand.ly', 'rb.gy', 'shorturl.at', 'tiny.cc'];
  var RISKY_TLDS = ['xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'click', 'link', 'live', 'buzz', 'rest', 'fit', 'icu', 'work', 'loan', 'win', 'vip', 'monster', 'online', 'site', 'club', 'cam'];

  function rx(list) { return list.map(function (s) { return new RegExp(s, 'i'); }); }
  function anyHit(patterns, text) { for (var i = 0; i < patterns.length; i++) { if (patterns[i].test(text)) return true; } return false; }

  var CAT = {
    urgency: rx([
      'urgent', 'immediately', 'act now', 'right away', 'final notice', 'last warning',
      'within \\d+ ?(hour|hr|day|min)', 'suspend', 'deactivat', 'clos(e|ing) your account',
      'account (will|has|is) .{0,12}(block|suspend|clos|lock)', 'limited time', 'expir(e|es|ing) (today|soon|now)',
      'عاجل', 'فور(اً|ا)', 'سيتم (إيقاف|حظر|إغلاق)', 'آخر تحذير', 'خلال \\d+ ساعة'
    ]),
    prize: rx([
      'you (have |’ve |\'ve )?won', 'congratulation', 'claim your (prize|reward|gift|money|winning)',
      'lottery', 'been selected', 'free (gift|iphone|prize|voucher)', 'inheritance',
      '(1[,. ]?000[,. ]?000|million)', 'ربح(ت)?', 'مبروك', 'جائزة', 'فزت', 'هدية مجانية', 'سحب'
    ]),
    credential: rx([
      'verify your (account|identity|card|number|phone|info)', 'confirm your (password|account|payment|identity|card)',
      'update your (payment|card|billing|account|info)', 'enter your (pin|password|otp|code|cvv)',
      'share (the |your )?(code|otp|pin)', 'your otp', 'reactivate your account',
      'login .{0,15}(verify|confirm|secure|unlock)', 'أدخل (الرمز|كلمة|الرقم السري)', 'رمز التحقق', 'أكّد (حسابك|هويتك)', 'حدّث (معلومات|بياناتك)'
    ]),
    payment: rx([
      // Scammers phrase the ask a hundred ways: "send $50", "send me 50 dollars",
      // "pay a small fee", "pay upfront". Match the shape, not one exact wording.
      'send\\b.{0,25}(\\$|\\d+\\s*(dollars?|usd|euros?|eur)|money|payment|cash)',
      'pay\\b.{0,25}(fee|charge|deposit|\\$|\\d+\\s*(dollars?|usd|euros?)|upfront|in advance)',
      '(fee|charge|deposit)\\b.{0,25}(to (claim|receive|unlock|release|get|collect)|before)',
      '(processing|handling|customs|release|delivery|activation|clearance|transfer|admin(istrative)?) (fee|charge|duty)',
      'small fee', 'advance payment',
      'wire transfer', 'gift ?card', 'western union', 'moneygram',
      '(bitcoin|btc|usdt|crypto|binance)', 'transfer .{0,20}(to claim|to receive|to unlock)',
      'حوّل|حوِّل|حول المبلغ', 'رسوم', 'بطاقة (هدية|شحن)', 'ادفع', 'دفعة مقدمة'
    ]),
    impersonation: rx([
      'your (package|parcel|shipment|delivery)', 'delivery (failed|attempt|pending|on hold)',
      'held at customs', 'your (bank|account) (has|was|is|will) ', 'security (alert|team|department)',
      'your (computer|device) (is|has been) (infected|hacked|at risk)', 'virus detected',
      'unusual (login|sign-in|activity)', 'suspicious (login|activity|transaction)',
      'طردك|شحنتك|إرسالية', 'فشل التوصيل', 'جمارك', 'حسابك (المصرفي|البنكي)', 'نشاط مشبوه'
    ]),
    threat: rx([
      'i (have|recorded|know your)', 'your (photos|videos|webcam|browsing history)',
      'i will (send|share|expose|post|leak)', 'pay .{0,20}(bitcoin|btc)', 'i hacked (your|you)'
    ])
  };
  var CAT_LABEL = {
    urgency: 'Pressure & urgency ("act now / your account will be closed")',
    prize: 'Prize / lottery bait ("you won")',
    credential: 'Asking for your password, PIN or code',
    payment: 'Asking you to send money or a fee',
    impersonation: 'Pretending to be a bank / delivery / company',
    threat: 'Threat or blackmail'
  };
  var CAT_WEIGHT = { urgency: 18, prize: 22, credential: 30, payment: 28, impersonation: 20, threat: 45 };

  function levelFromScore(score) {
    if (score >= 60) return 'danger';
    if (score >= 25) return 'warning';
    return 'safe';
  }

  // ---- URL analysis -------------------------------------------------------
  function extractUrls(text) {
    var out = [], m;
    var re = /((https?:\/\/)?([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?:\/[^\s]*)?)/gi;
    while ((m = re.exec(text)) !== null) {
      var u = m[1];
      if (/\.[a-z]{2,}/i.test(u) && !/^\d+(\.\d+)+$/.test(u.replace(/^https?:\/\//i, '').split('/')[0])) out.push(u);
      // also allow IP urls
    }
    // IP-based
    var ipRe = /(https?:\/\/)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?(\/[^\s]*)?/g;
    while ((m = ipRe.exec(text)) !== null) out.push(m[0]);
    return out;
  }

  function parseHost(raw) {
    var s = String(raw).trim();
    var scheme = '';
    var mm = s.match(/^([a-z][a-z0-9+.\-]*):\/\//i);
    if (mm) { scheme = mm[1].toLowerCase(); s = s.slice(mm[0].length); }
    var authority = s.split(/[\/?#]/)[0];
    var userinfo = '';
    if (authority.indexOf('@') !== -1) {
      var p = authority.split('@');
      userinfo = p.slice(0, -1).join('@');
      authority = p[p.length - 1];
    }
    var host = authority.split(':')[0].toLowerCase();
    return { scheme: scheme, host: host, userinfo: userinfo };
  }

  function analyzeUrl(raw) {
    var reasons = [], score = 0;
    var info = parseHost(raw);
    var host = info.host;
    var labels = host.split('.');
    var tld = labels[labels.length - 1] || '';
    var registrable = labels.length >= 2 ? labels[labels.length - 2] : host;

    var isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
    if (isIp) { score += 55; reasons.push('The link goes to a raw number address, not a real website name — almost always a scam.'); }

    if (info.userinfo) { score += 55; reasons.push('The link uses the "@" trick — what looks like the real site is fake; it actually goes somewhere else.'); }

    if (host.indexOf('xn--') !== -1) { score += 40; reasons.push('The web address uses disguised look-alike letters (fake alphabet).'); }

    var short = SHORTENERS.indexOf(host) !== -1 || SHORTENERS.indexOf(registrable + '.' + tld) !== -1;
    if (short) { score += 30; reasons.push('It uses a link-shortener that hides the real destination — you can’t see where it leads.'); }

    if (RISKY_TLDS.indexOf(tld) !== -1) { score += 22; reasons.push('The web address ends in ".' + tld + '", an ending scammers use a lot.'); }

    // Brand look-alike: a known brand appears in the host, but the real domain
    // label is NOT that brand → impersonation (whish-money.xyz, secure.whish.top…)
    if (!isIp) {
      for (var i = 0; i < BRANDS.length; i++) {
        var b = BRANDS[i];
        if (host.indexOf(b) !== -1 && registrable !== b) {
          score += 40;
          reasons.push('The link pretends to be "' + b + '" but the real address is different — a fake look-alike.');
          break;
        }
      }
    }

    var hyphens = (host.match(/-/g) || []).length;
    if (hyphens >= 3) { score += 12; reasons.push('The web address has many dashes, a common trick.'); }
    if (host.length >= 40) { score += 8; reasons.push('The web address is unusually long.'); }

    if (info.scheme === 'http') { score += 8; reasons.push('The link is not secure (plain "http").'); }

    if (score === 0) reasons.push('No obvious danger signs in this link — but stay careful.');
    return { type: 'link', score: score, level: levelFromScore(score), reasons: reasons };
  }

  // ---- Message analysis ---------------------------------------------------
  function analyzeMessage(text) {
    var reasons = [], score = 0, hitCats = {};
    for (var k in CAT) {
      if (anyHit(CAT[k], text)) { hitCats[k] = true; score += CAT_WEIGHT[k]; reasons.push(CAT_LABEL[k]); }
    }
    // Money talk on its own is everyday life — "I'll send you money tomorrow",
    // "the delivery fee is included". An ask for money is only a red flag when
    // it rides with bait, pressure, impersonation or a threat. So a lone
    // payment mention must not raise an alarm, or we cry wolf on normal chat.
    var catCount = 0; for (var c in hitCats) catCount++;
    if (catCount === 1 && hitCats.payment) {
      score -= 16;
      var pi = reasons.indexOf(CAT_LABEL.payment);
      if (pi !== -1) reasons[pi] = 'This mentions money. On its own that is normal — but never send money or a code to someone you do not know.';
    }

    // Classic combos deserve a boost.
    if (hitCats.urgency && hitCats.credential) { score += 15; reasons.push('Pressure + a request for your secret code = classic phishing.'); }
    if (hitCats.prize && hitCats.payment) { score += 15; reasons.push('A "prize" that asks you to pay first = classic advance-fee scam.'); }

    // Any links inside the message get checked too, and the worst one counts.
    var urls = extractUrls(text), worst = null;
    for (var i = 0; i < urls.length; i++) {
      var u = analyzeUrl(urls[i]);
      if (!worst || u.score > worst.score) worst = u;
    }
    if (worst && worst.score >= 25) {
      score += Math.round(worst.score * 0.6);
      reasons.push('It contains a suspicious link: ' + worst.reasons[0]);
    } else if (urls.length && worst && worst.score < 25) {
      reasons.push('Contains a link — never tap a link in a message you did not expect.');
      score += 5;
    }

    if (score === 0) reasons.push('No common scam signs found — but no message tool is perfect. If it involves money or a code, be careful.');
    return { type: 'message', score: score, level: levelFromScore(score), reasons: reasons };
  }

  // ---- Phone analysis (offline is limited — honest about it) --------------
  function analyzePhone(raw) {
    var reasons = [], score = 0;
    var s = String(raw).trim();
    var letters = (s.match(/[a-zء-ي]/gi) || []).length;
    var digits = (s.match(/\d/g) || []).length;

    if (letters > 0 && digits < 4) {
      score += 20;
      reasons.push('This is a named sender ("' + s + '"), not a real number — sender names are very easy to fake.');
    }
    if (digits > 0 && digits <= 5) {
      score += 15;
      reasons.push('Very short number (a "short code") — used for both real services and scams.');
    }
    reasons.push('Offline, I can’t look up a phone number. Tap "Deep check" to look it up online, or just don’t answer unknown numbers.');
    return { type: 'phone', score: score, level: score >= 25 ? 'warning' : 'unknown', reasons: reasons, deepCheck: true };
  }

  // ---- The cold opener ----------------------------------------------------
  // The most common scam opener on earth, and the hardest to see: a stranger
  // sends one bare "hello". No link, nothing to click — that is exactly why it
  // works. He is not chatting; he is finding out whether a real person holds
  // this number. Everyone who answers gets moved to the next stage.
  // Offline we cannot know if the sender is a friend, so we do not scream
  // "scam" — we ask the one question that decides it: do you know this person?
  var GREET_EN = /(^|\s)(hi+|hey+|hell?o+|good\s+(morning|evening|afternoon|day)|how\s+(are\s+you|r\s+u)|dear|friend|sir|madam|miss|wrong\s+number|is\s+this\s+(you|your\s+number)|salam|salaam|assalam|marhaba|kifak|kifik)(?=\s|$)/gi;
  var GREET_AR = /(مرحبا|أهلا|اهلا|هلا|حياك|السلام عليكم|سلام|صباح الخير|مساء الخير|كيف حالك|كيفك|شلونك|عزيزي|عزيزتي)/g;

  function normalizeGreeting(s) {
    return String(s)
      .replace(/[ً-ْـ]/g, '')          // Arabic diacritics + tatweel: مرحبًا -> مرحبا
      .replace(/[^a-z؀-ۿ\s]/gi, ' ')        // drop emoji, punctuation, digits — keep letters
      .replace(/\s+/g, ' ')
      .trim().toLowerCase();
  }

  function isColdOpener(text) {
    var t = normalizeGreeting(text);
    if (!t) return false;
    if (t.split(' ').length > 6) return false;        // a real sentence, not a lone greeting
    var left = t.replace(GREET_EN, ' ').replace(GREET_AR, ' ').replace(/\s+/g, ' ').trim();
    return left.length <= 2;                          // nothing but the greeting remains
  }

  function analyzeColdOpener() {
    return {
      type: 'greeting', score: 45, level: 'warning', deepCheck: true,
      reasons: [
        'This is only a greeting — no link, nothing to click. That is exactly why it works.',
        'A stranger who sends a lone "hello" is not chatting. He is checking whether a real person holds this number. Everyone who answers is moved to the next step: a few friendly days, then an "investment", or an emergency that needs money.',
        'If this person IS in your contacts, it is very likely just a friend saying hello.'
      ],
      todo: 'What to do: If you do not know this person — do NOT reply, not even "wrong number". Any answer proves your number is real and alive. Block them and delete the chat.'
    };
  }

  // ---- Type detection + main entry ---------------------------------------
  function detectType(s) {
    s = String(s).trim();
    var hasUrl = /(https?:\/\/|www\.|(^|\s)[a-z0-9-]+\.[a-z]{2,}(\/|$|\s))/i.test(s) ||
      /\d{1,3}(\.\d{1,3}){3}/.test(s);
    var nonPhone = s.replace(/[\d+\-() .]/g, '');
    var digits = (s.match(/\d/g) || []).length;
    if (!hasUrl && digits >= 6 && nonPhone.length <= 3) return 'phone';
    if (hasUrl && s.split(/\s+/).length <= 2) return 'url';
    return 'message';
  }

  function analyze(input, hint) {
    var text = String(input == null ? '' : input);
    if (!text.trim()) return { type: 'empty', score: 0, level: 'unknown', reasons: ['Nothing to check yet.'], deepCheck: false };
    var trimmed = text.trim();

    // Check for the lone greeting FIRST — otherwise "hello" / "مرحبًا" falls into
    // the sender-name branch below and the app says nothing useful about the
    // single most common scam opener there is.
    if ((!hint || hint === 'auto') && isColdOpener(trimmed)) return analyzeColdOpener();

    // A lone word with letters, no dot, no long number = an SMS "sender name",
    // not a real message. We must NOT call it a scam (that would false-alarm on
    // every genuine "WHISH" / "Bank" text) — but we tell the truth: the name is
    // fakeable, and the message body is what matters.
    if ((!hint || hint === 'auto') &&
        trimmed.split(/\s+/).length === 1 &&
        trimmed.indexOf('.') === -1 &&
        /[a-zء-ي]/i.test(trimmed) &&
        !/\d{4,}/.test(trimmed) &&
        trimmed.length <= 20) {
      var isBrand = BRANDS.indexOf(trimmed.toLowerCase()) !== -1;
      return {
        type: 'sender', score: 0, level: 'unknown', deepCheck: false,
        reasons: [(isBrand ? 'That is only the sender name "' + trimmed + '". ' : 'This looks like a sender name, not a full message. ') +
          'Sender names are very easy to fake — a scammer can show any name. Paste the WHOLE message so I can check what it actually says.']
      };
    }

    var type = (hint && hint !== 'auto') ? hint : detectType(text);
    var result = type === 'phone' ? analyzePhone(text) : type === 'url' ? analyzeUrl(text) : analyzeMessage(text);
    // Recommend the online deep check when offline is unsure or sees mild risk,
    // or always for phones (offline can't verify a number).
    if (result.deepCheck === undefined) {
      result.deepCheck = result.level === 'warning' || (result.level === 'safe' && result.score > 0);
    }
    result.score = Math.min(100, result.score);
    return result;
  }

  var ScamEngine = { analyze: analyze, analyzeMessage: analyzeMessage, analyzeUrl: analyzeUrl, analyzePhone: analyzePhone, detectType: detectType };

  if (typeof module !== 'undefined' && module.exports) module.exports = ScamEngine;
  root.ScamEngine = ScamEngine;
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
