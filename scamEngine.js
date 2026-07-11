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
      'reactivate your account', 'login .{0,15}(verify|confirm|secure|unlock)',
      'أدخل (الرمز|كلمة|الرقم السري)', 'أكّد (حسابك|هويتك)', 'حدّث (معلومات|بياناتك)'
    ]),
    // Handing over the one-time code from your phone — near-always a scam (no
    // real service asks you to reply with it). Kept separate from "enter your
    // code" so we can escalate it hard. Tightened so it does NOT fire on a
    // promo/discount/source "code" — it needs an OTP/PIN/verification code, a
    // "digit code", or the "code we sent / code sent to your phone" shape.
    otp_ask: rx([
      '(reply|respond|text|forward|send|give|tell|share) .{0,18}(the )?(\\d-?digit |verification |security |one[- ]?time )?(otp|pin)\\b',
      '(reply|respond|text|forward|send|give|tell|share) .{0,18}(the )?(\\d-?digit|verification|security|one[- ]?time) code',
      '\\b\\d-?digit (code|pin|otp)',
      '(the )?(\\d-?digit |verification |security |one[- ]?time )?code .{0,14}(we|i) .{0,6}(just )?sent',
      'code .{0,10}(sent to|on) your (phone|number|mobile)',
      '(whatsapp|sms|login|activation|verification|security|authentication|one[- ]?time|access) code',
      'رمز التحقق', 'الرمز السري', 'الرمز الذي (وصلك|أرسلناه|بعتناه)', '(أرسل|ابعت|شارك|زودني) .{0,12}(رمز التحقق|الرمز السري|الكود)'
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
      'i will (send|share|expose|post|leak)', 'pay .{0,20}(bitcoin|btc)', 'i hacked (your|you)',
      'سج(ّ)?لت', 'اخترقت', 'صور(ك)? خاصة', 'سأنشر'
    ]),
    // Investment / pig-butchering — the slow-trust crypto trap. Requires the
    // scammy SHAPE (guaranteed profit, crypto "opportunity"), not the bare word.
    investment: rx([
      'guaranteed (profit|return|income|money)', 'double your (money|investment|capital)',
      '(crypto|bitcoin|forex|binary option|trading) (invest|profit|signal|platform|opportunity|group)',
      'invest .{0,20}(crypto|bitcoin|forex|and (earn|profit)|guaranteed|small amount)',
      'high (returns|profit)', 'profit (daily|every ?day|guaranteed|of \\d)',
      'i (can|will) (teach|help|show) you (how )?(to )?(invest|trade|earn|make money)',
      'financial freedom', '(signal|vip) group .{0,12}(profit|trade|crypto|invest)',
      'استثمار (مضمون|مربح)', 'ربح مضمون', 'أرباح يومية', 'تداول', 'عمل(ة|ات) رقمية', 'ضاعف أموالك', 'محفظة استثمار'
    ]),
    // Task / job scams — "easy money from home", pay-to-unlock, commission bait.
    task_job: rx([
      '(work|job|earn) .{0,20}(from home|online).{0,20}(earn|\\$|salary|daily|money)',
      'earn .{0,15}(\\$|\\d+).{0,18}(daily|per ?day|a day|from home|online|easy)',
      '(rate|like|review|boost|optimize) (products|apps|hotels|videos|posts|orders) .{0,18}(earn|money|\\$|paid|commission)',
      'part[- ]?time .{0,16}(online|remote|earn|\\$)', 'no experience (needed|required)',
      'simple (task|job).{0,16}(earn|paid|\\$|daily)', 'commission (per|for each|on each) (task|order|like|referral)',
      'complete .{0,10}tasks?.{0,18}(earn|get paid|\\$|commission)', '(unlock|vip) .{0,12}(task|level|set).{0,16}(deposit|pay|top ?up)',
      'وظيفة (من المنزل|عن بعد)', 'اربح من المنزل', 'دخل (يومي|إضافي)', 'عمولة', 'مهام بسيطة', 'راتب يومي'
    ]),
    // Family-emergency / "new number" — impersonating your child/relative.
    family_new_number: rx([
      'this is my new number', 'i (lost|broke|changed|damaged) my phone', 'i (have|got) a new (number|phone|sim)',
      'save (this as )?my new number', 'new whatsapp number', 'it(\'|’)?s me,? (mom|mum|dad|your son|your daughter)',
      '(hi|hello|hey) (mom|mum|dad|mother|father)\\b', 'my (old )?(phone|number) (is|got|was) (broken|lost|stolen)',
      'رقمي الجديد', 'ضاع (هاتفي|تلفوني|جوالي)', 'غيرت رقمي', 'رقم(ي)? جديد', 'أنا (ابنك|ابنتك|أمك|أبوك|ولدك)'
    ]),
    // Refund / tech-support — "you were charged", "call us", "install remote access".
    refund_support: rx([
      'refund (department|team|desk|of \\$|has been|is due|will be)', 'you (will|have) be(en)? (charged|billed) .{0,18}(renew|subscription|membership)',
      'your (subscription|membership|antivirus|order|plan) (was|has been|is|will be) (renewed|charged|auto[- ]?renewed|debited)',
      '(anydesk|teamviewer|remote ?desktop|remote access|screen ?share)', 'install .{0,18}(to (fix|refund|connect|verify)|our (app|tool|software))',
      'call (us|this|our) .{0,12}(number|helpline|hotline|support|team)', '(tech|technical|customer) support .{0,15}(call|number|team)',
      'your (computer|device|pc|account) (is|has been|was) (infected|hacked|compromised|at risk)',
      'اتصل ب(الدعم|الرقم|فريق)', 'تم تجديد (اشتراك|عضوية)', 'استرداد (المبلغ|أموال)', 'دعم فني', 'جهازك (مصاب|مخترق)'
    ]),
    // Authority impersonation — police / court / tax threatening you. Low weight
    // alone (mentions happen); the danger comes from the combo with pay/urgency.
    authority: rx([
      'arrest (warrant|you|is)', 'warrant .{0,12}(issued|out|for your)', 'legal action (will|against|taken)',
      '(tax|irs|customs|immigration|social security|court|police|interpol|fbi) .{0,24}(you owe|owe|pay|fine|penalty|seized|on hold|detained|lawsuit)',
      'you (owe|have (a )?(fine|penalty|unpaid)|must pay) .{0,18}(tax|fine|penalty|court|government|customs)',
      'مذكرة (توقيف|اعتقال|قضائية)', 'مخالفة .{0,12}(دفع|سداد)', 'الجمارك .{0,15}(احتجاز|دفع|رسوم)', 'ضريبة .{0,12}(متأخرة|مستحقة)', 'ملاحقة قانونية'
    ]),
    // Untraceable payment rails — gift cards, crypto, wire. Near-universal scam
    // tell: a REQUEST to pay this way (not just a mention).
    untraceable_pay: rx([
      '(pay|send|buy|purchase|load|get).{0,26}(gift ?card|itunes|google ?play card|steam card|amazon card|apple card|prepaid card)',
      '(pay|send|transfer).{0,22}(in |with |via |by |through )?(bitcoin|btc|usdt|crypto|ethereum|binance)',
      '(wire|western union|moneygram).{0,18}(transfer|money|the (fee|amount|money))',
      'bitcoin (atm|wallet|address)', 'send (me )?(the )?(code|number|photo) (of|on|from) the (gift ?card)',
      'ادفع .{0,15}(بطاقة|بيتكوين|كريبتو)', 'بطاقة (جوجل|جوجل بلاي|آيتونز|ايتونز|هدية|شحن)', '(عبر|من خلال) (ويسترن يونيون|بيتكوين)', 'محفظة بيتكوين'
    ])
  };
  var CAT_LABEL = {
    urgency: 'Pressure & urgency ("act now / your account will be closed")',
    prize: 'Prize / lottery bait ("you won")',
    credential: 'Asking you to verify / enter your account details',
    otp_ask: 'Asking for the one-time code sent to your phone (OTP)',
    payment: 'Asking you to send money or a fee',
    impersonation: 'Pretending to be a bank / delivery / company',
    threat: 'Threat or blackmail',
    investment: 'An "investment" promising guaranteed or fast profit',
    task_job: 'Easy-money job bait ("earn from home / rate products")',
    family_new_number: 'Someone claiming to be family from a "new number"',
    refund_support: 'Fake refund / tech-support ("call this number / install this")',
    authority: 'A "police / court / tax" threat demanding payment',
    untraceable_pay: 'Asking to pay by gift card, crypto or wire (untraceable)'
  };
  var CAT_WEIGHT = {
    urgency: 18, prize: 22, credential: 30, otp_ask: 34, payment: 28, impersonation: 20, threat: 45,
    investment: 26, task_job: 26, family_new_number: 26, refund_support: 26, authority: 16, untraceable_pay: 30
  };

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

  // ---- Name the scam + give the exact advice for its type -----------------
  // Once we know which signals fired, we can tell the user WHAT kind of scam
  // this is and the one right thing to do about it. Order = most specific /
  // most dangerous first. `bonus` escalates when a tell-tale pair is present.
  function classifyScam(h) {
    var untr = !!h.untraceable_pay, pay = !!h.payment || untr;
    if (h.threat)
      return { name: 'a sextortion / blackmail scam', bonus: 0,
        todo: 'What to do: Do NOT pay and do NOT reply. This is a bulk bluff sent to thousands — they almost never have anything. Paying only marks you as easy. Block and delete.' };
    if (h.otp_ask)
      return { name: 'an OTP / bank-code phishing scam', bonus: 26,
        todo: 'What to do: NEVER share the code from your phone — not with "the bank", "WhatsApp", "support", or anyone. That code is the key to your account; no real company ever asks you to send it. Delete and block.' };
    if (h.family_new_number)
      return { name: 'a "family / new number" scam', bonus: pay ? 22 : 0,
        todo: 'What to do: STOP — before you send anything, call the real person on their OLD number, or ask another relative. Scammers pose as your son, daughter or parent on a "new number" and invent an emergency. Real family will not mind you checking first.' };
    if (h.investment)
      return { name: 'an investment / "pig-butchering" scam', bonus: (untr || h.urgency) ? 16 : 0,
        todo: 'What to do: No real investment guarantees profit. Never send money or crypto to someone who contacted you — however friendly or patient they were. If they say "don’t tell anyone", that alone proves it is a scam.' };
    if (h.task_job)
      return { name: 'a task / job scam', bonus: pay ? 18 : 0,
        todo: 'What to do: A real job never asks you to pay, deposit, or "unlock" anything to get paid. The small early payment is the bait to make you trust it. Stop before you deposit a single lira.' };
    if (h.authority)
      return { name: 'an authority-impersonation scam ("police / court / tax")', bonus: (pay || h.urgency) ? 18 : 0,
        todo: 'What to do: Real police, courts and tax offices never phone or text demanding payment by card, crypto or transfer, and never threaten instant arrest. Hang up. Call the real office yourself using an official number.' };
    if (h.refund_support)
      return { name: 'a refund / tech-support scam', bonus: (untr || h.credential) ? 15 : 0,
        todo: 'What to do: No real company needs remote access to your device, and none pays refunds by gift card. Do not install anything, do not call the number, and never let anyone connect to your phone.' };
    if (h.prize && pay)
      return { name: 'a prize / advance-fee scam', bonus: 15,
        todo: 'What to do: A real prize never asks you to pay first. Send nothing, and delete it.' };
    if (h.urgency && h.credential)
      return { name: 'a phishing scam', bonus: 15,
        todo: 'What to do: Never type your password or the code from your phone into a link. Your bank will never ask for it. If unsure, open the app yourself — do not use their link.' };
    if (h.impersonation && (h.urgency || h.credential || pay))
      return { name: 'a fake-company / phishing message', bonus: 10,
        todo: 'What to do: Do not tap the link or reply. Reach the company yourself — their app, or a number you already have — never through a link inside the message.' };
    if (untr)
      return { name: 'a scam (it wants an untraceable payment)', bonus: 30,
        todo: 'What to do: Anyone asking to be paid by gift card, crypto or Western Union is almost always a scammer — those cannot be traced or refunded. Do not pay.' };
    return null;
  }

  // ---- Message analysis ---------------------------------------------------
  function analyzeMessage(text) {
    var reasons = [], score = 0, hitCats = {}, todo = null;
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

    // Name the scam type and attach the exact advice for it.
    var cls = classifyScam(hitCats);
    if (cls) {
      score += cls.bonus;
      reasons.unshift('🔎 This looks like ' + cls.name + '.');
      todo = cls.todo;
    }

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
    var out = { type: 'message', score: score, level: levelFromScore(score), reasons: reasons };
    if (todo) out.todo = todo;
    return out;
  }

  // ---- Phone analysis (offline is limited — honest about it) --------------
  // The phone's own country. A number from somewhere else is the first thing
  // the app can read offline — and often the loudest signal.
  var HOME_CC = '961'; // Lebanon
  // Country code -> name, for the "aha, it's Cuba" moment.
  var CC_NAME = {
    '1':'the US/Canada','7':'Russia','20':'Egypt','27':'South Africa','30':'Greece','31':'the Netherlands',
    '32':'Belgium','33':'France','34':'Spain','36':'Hungary','39':'Italy','40':'Romania','41':'Switzerland',
    '43':'Austria','44':'the UK','45':'Denmark','46':'Sweden','47':'Norway','48':'Poland','49':'Germany',
    '51':'Peru','52':'Mexico','53':'Cuba','54':'Argentina','55':'Brazil','56':'Chile','57':'Colombia','58':'Venezuela',
    '60':'Malaysia','61':'Australia','62':'Indonesia','63':'the Philippines','64':'New Zealand','65':'Singapore',
    '66':'Thailand','81':'Japan','82':'South Korea','84':'Vietnam','86':'China','90':'Turkey','91':'India',
    '92':'Pakistan','93':'Afghanistan','94':'Sri Lanka','95':'Myanmar','98':'Iran',
    '211':'South Sudan','212':'Morocco','213':'Algeria','216':'Tunisia','218':'Libya','220':'Gambia','221':'Senegal',
    '223':'Mali','225':'Ivory Coast','226':'Burkina Faso','229':'Benin','231':'Liberia','233':'Ghana','234':'Nigeria',
    '237':'Cameroon','243':'DR Congo','249':'Sudan','251':'Ethiopia','252':'Somalia','254':'Kenya','255':'Tanzania',
    '256':'Uganda','260':'Zambia','263':'Zimbabwe','351':'Portugal','352':'Luxembourg','353':'Ireland','355':'Albania',
    '357':'Cyprus','358':'Finland','359':'Bulgaria','370':'Lithuania','371':'Latvia','372':'Estonia','373':'Moldova',
    '374':'Armenia','375':'Belarus','380':'Ukraine','381':'Serbia','383':'Kosovo','385':'Croatia','386':'Slovenia',
    '387':'Bosnia','389':'North Macedonia','420':'Czechia','421':'Slovakia','852':'Hong Kong','855':'Cambodia',
    '856':'Laos','880':'Bangladesh','886':'Taiwan','960':'the Maldives','961':'Lebanon','962':'Jordan','963':'Syria',
    '964':'Iraq','965':'Kuwait','966':'Saudi Arabia','967':'Yemen','968':'Oman','970':'Palestine','971':'the UAE',
    '972':'Israel','973':'Bahrain','974':'Qatar','976':'Mongolia','977':'Nepal','992':'Tajikistan','993':'Turkmenistan',
    '994':'Azerbaijan','995':'Georgia','996':'Kyrgyzstan','998':'Uzbekistan',
    '870':'a satellite phone','881':'a satellite phone','882':'an international network','883':'an international network'
  };
  // Countries a Lebanese person plausibly has family/work ties to → gentler tone.
  var FAMILIAR_CC = {'971':1,'966':1,'974':1,'965':1,'973':1,'968':1,'967':1,'20':1,'963':1,'962':1,'964':1,
    '970':1,'972':1,'90':1,'98':1,'1':1,'44':1,'33':1,'49':1,'39':1,'46':1,'45':1,'31':1,'32':1,'41':1,'34':1,
    '61':1,'55':1,'234':1,'225':1,'233':1,'351':1,'357':1,'358':1,'46':1,'47':1};

  // Reads the country code off an international number (+CC… or 00CC…).
  function readCountry(s) {
    var d = String(s).replace(/[^\d+]/g, '');
    var rest;
    if (d.charAt(0) === '+') rest = d.slice(1);
    else if (d.slice(0, 2) === '00') rest = d.slice(2);
    else return { intl: false };
    for (var len = 3; len >= 1; len--) {
      var cc = rest.slice(0, len);
      if (CC_NAME[cc]) return { intl: true, cc: cc, name: CC_NAME[cc] };
    }
    return { intl: true, cc: null, name: null };
  }

  function analyzePhone(raw) {
    var reasons = [], score = 0, todo = null;
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

    // The big offline signal: where is this number from?
    var geo = readCountry(s);
    if (geo.intl && geo.cc !== HOME_CC) {
      if (geo.name && !FAMILIAR_CC[geo.cc]) {
        score += 35;
        reasons.push('This number is from ' + geo.name + ' — a country you most likely have no ties to.');
        reasons.push('A call, or a one-ring "missed call", from a far country is a classic trap: you call back and it is a paid line that charges you by the minute — and some of that money goes to the scammer.');
        todo = 'What to do: Do NOT call back and do NOT save it. If you do not know anyone in ' + geo.name + ', block the number. Let a real caller leave a message.';
      } else if (geo.name) {
        score += 15;
        reasons.push('This number is from ' + geo.name + '. If you know someone there it may be fine — but if you do NOT, be careful and never call back an unknown foreign number.');
      } else {
        score += 30;
        reasons.push('This is an international number from outside Lebanon. If you were not expecting a foreign call, a "call-back" trap charges you premium rates when you return the call.');
        todo = 'What to do: Don’t call back an unknown foreign number. If it matters, they will message or leave a voicemail.';
      }
    }

    reasons.push('Offline, I can’t look up who owns a number. For a deeper look tap the AI — or simply don’t answer numbers you don’t know.');
    var result = { type: 'phone', score: score, level: score >= 25 ? 'warning' : 'unknown', reasons: reasons, deepCheck: true };
    if (todo) result.todo = todo;
    return result;
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
