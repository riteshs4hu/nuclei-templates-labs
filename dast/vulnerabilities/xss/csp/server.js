const express = require('express');

const getDomainFromUrl = (url) => {
  // Extract the main domain from the URL
  const matches = url.match(/^https?:\/\/(?:[^\/]+\.)?([^\/]+\.[^\/]+)$/);
  return matches ? matches[1] : null;
};

const createServer = (port, cspDomain, domainName, title) => {
  const app = express();

  app.use((req, res, next) => {
    const mainDomain = getDomainFromUrl(cspDomain);
    // Use the full domain for the specific source, but the main domain for wildcarded subdomains
    const cspHeader = `default-src 'self'; script-src 'self' ${cspDomain} *.${mainDomain}`;
    res.setHeader("Content-Security-Policy", cspHeader);
    next();
  });

  app.get('/', (req, res) => {
    res.send(`
      <html>
        <head>
          <title>${title}</title>
        </head>
        <body>
          <h1>Demo for ${cspDomain}</h1>
          <p>This is a simple demo page for ${cspDomain}.</p>
        </body>
      </html>
    `);
  });

  app.get('/xss', (req, res) => {
    const payload = req.query.payload || 'test';
    res.send(`
      <html>
        <head>
          <title>XSS Test</title>
        </head>
        <body>
          <h1>XSS Test for ${cspDomain}</h1>
          <div>${payload}</div>
        </body>
      </html>
    `);
  });

  app.listen(port, () => {
    console.log(`Server for ${domainName} running at http://localhost:${port}`);
  });
};

// Create servers for all domains
const domains = [
  ['7b936.v.fwmrm.net', 2000],
  ['a.huodong.mi.com', 2001],
  ['acs.aliexpress.com', 2002],
  ['aax-eu.amazon.com', 2003],
  ['accdn.lpsnmedia.net', 2004],
  ['accounts.google.com', 2005],
  ['acs.youku.com', 2006],
  ['ads.yap.yahoo.com', 2007],
  ['ajax.googleapis.com', 2008],
  ['analytics.tiktok.com', 2009],
  ['anchor.digitalocean.com', 2010],
  ['a.config.skype.com', 2011],
  ['ap.lijit.com', 2012],
  ['api.bazaarvoice.com', 2013],
  ['api.bing.com', 2014],
  ['api.chartbeat.com', 2015],
  ['api.cxense.com', 2016],
  ['api.dailymotion.com', 2017],
  ['api.duckduckgo.com', 2018],
  ['api.facebook.com', 2019],
  ['api.flickr.com', 2020],
  ['api.forismatic.com', 2021],
  ['api.getdrip.com', 2022],
  ['api.github.com', 2023],
  ['api.ipify.org', 2024],
  ['api.m.jd.com', 2025],
  ['api.map.baidu.com', 2026],
  ['api.meetup.com', 2027],
  ['api.microsofttranslator.com', 2028],
  ['api.mixpanel.com', 2029],
  ['api.olark.com', 2030],
  ['api.pinterest.com', 2031],
  ['api.stackexchange.com', 2032],
  ['api.swiftype.com', 2033],
  ['api.twitter.com', 2034],
  ['api.tumblr.com', 2035],
  ['api.livechatinc.com', 2036],
  ['api.vk.com', 2037],
  ['api.wordpress.org', 2038],
  ['api.x.com', 2039],
  ['apis.google.com', 2040],
  ['app-sjint.marketo.com', 2041],
  ['app.link', 2042],
  ['apps.bdimg.com', 2043],
  ['assets.grubhub.com', 2044],
  ['bebezoo.1688.com', 2045],
  ['bookmark.hatenaapis.com', 2046],
  ['c.y.qq.com', 2047],
  ['cas.criteo.com', 2048],
  ['cdn.arkoselabs.com', 2049],
  ['cdn.jsdelivr.net', 2050],
  ['cdn.shopify.com', 2051],
  ['cdn.syncfusion.com', 2052],
  ['cdnjs.cloudflare.com', 2053],
  ['challenges.cloudflare.com', 2054],
  ['client-api.arkoselabs.com', 2055],
  ['client.crisp.chat', 2056],
  ['code.angularjs.org', 2057],
  ['commerce.coinbase.com', 2058],
  ['common.like.naver.com', 2059],
  ['connect.mail.ru', 2060],
  ['content.akamai.com', 2061],
  ['cse.google.com', 2062],
  ['clients1.google.com', 2063],
  ['d.adroll.com', 2064],
  ['d1xrp9zhb3ks3c.cloudfront.net', 2065],
  ['dblp.org', 2066],
  ['demo.matomo.cloud', 2067],
  ['dev.virtualearth.net', 2068],
  ['developer.apple.com', 2069],
  ['documentation-resources.opendatasoft.com', 2070],
  ['don.bild.de', 2071],
  ['dpm.demdex.net', 2072],
  ['dynamic.criteo.com', 2073],
  ['elysiumwebsite.s3.amazonaws.com', 2074],
  ['eu.battle.net', 2075],
  ['fast.wistia.com', 2076],
  ['forms.hsforms.com', 2077],
  ['forms.hubspot.com', 2078],
  ['geo.moatads.com', 2079],
  ['geolocation.onetrust.com', 2080],
  ['gist.github.com', 2081],
  ['global.apis.naver.com', 2082],
  ['go.dev', 2083],
  ['go.snyk.io', 2084],
  ['graph.facebook.com', 2085],
  ['gstatic.com', 2086],
  ['gum.criteo.com', 2087],
  ['hcaptcha.com', 2088],
  ['help.afterpay.com', 2089],
  ['ib.adnxs.com', 2090],
  ['info.cloudflare.com', 2091],
  ['info.elastic.co', 2092],
  ['inno.blob.core.windows.net', 2093],
  ['investor.coinbase.com', 2094],
  ['ipinfo.io', 2095],
  ['itunes.apple.com', 2096],
  ['js-smb.devices.ovoenergy.com', 2097],
  ['js.hcaptcha.com', 2098],
  ['kbcprod.service-now.com', 2099],
  ['lghnh-mkt-prod1.campaign.adobe.com', 2100],
  ['lptag.liveperson.net', 2101],
  ['links.services.disqus.com', 2102],
  ['m.media-amazon.com', 2103],
  ['mango.buzzfeed.com', 2104],
  ['maps-api-ssl.google.com', 2105],
  ['maps.google.com', 2106],
  ['maps.google.de', 2107],
  ['maps.google.lv', 2108],
  ['maps.google.ru', 2109],
  ['maps.googleapis.com', 2110],
  ['mc.yandex.ru', 2111],
  ['nominatim.openstreetmap.org', 2112],
  ['oamssoqae.ieee.org', 2113],
  ['openexchangerates.org', 2114],
  ['page.gitlab.com', 2115],
  ['partner.googleadservices.com', 2116],
  ['passport.baidu.com', 2117],
  ['pixel.mathtag.com', 2118],
  ['pixel.quantserve.com', 2119],
  ['portal.ayco.com', 2120],
  ['pubads.g.doubleclick.net', 2121],
  ['public-api.wordpress.com', 2122],
  ['query.fqtag.com', 2123],
  ['r.skimresources.com', 2124],
  ['raae2vza0snymz9cm3r8ix74bs71vdlz.edns.ip-api.com', 2125],
  ['recaptcha.net', 2126],
  ['rentokil-domains.firebaseio.com', 2127],
  ['reveal.clearbit.com', 2128],
  ['ring.com', 2129],
  ['romania.amazon.com', 2130],
  ['s.fqtag.com', 2131],
  ['s.ytimg.com', 2132],
  ['search.yahoo.com', 2133],
  ['secure.adnxs.com', 2134],
  ['secure.gravatar.com', 2135],
  ['secure.quantserve.com', 2136],
  ['securepubads.g.doubleclick.net', 2137],
  ['segapi.quantserve.com', 2138],
  ['server.ethicalads.io', 2139],
  ['shop.samsung.com', 2140],
  ['smartcaptcha.yandexcloud.net', 2141],
  ['social.yandex.ru', 2142],
  ['soundcloud.com', 2143],
  ['srv.carbonads.net', 2144],
  ['ssl.gstatic.com', 2145],
  ['sso.bytedance.com', 2146],
  ['st3.zoom.us', 2147],
  ['static.parastorage.com', 2148],
  ['storage.googleapis.com', 2149],
  ['storemapper-herokuapp-com.global.ssl.fastly.net', 2150],
  ['suggest.taobao.com', 2151],
  ['suggestqueries-clients6.youtube.com', 2152],
  ['support.zendesk.com', 2153],
  ['sync.im-apps.net', 2154],
  ['tagmanager.google.com', 2155],
  ['tcr9i.openai.com', 2156],
  ['thehive.shopify.io', 2157],
  ['thiscanbeanything.zendesk.com', 2158],
  ['translate.google.com', 2159],
  ['translate.googleapis.com', 2160],
  ['translate.yandex.net', 2161],
  ['tr.indeed.com', 2162],
  ['udgnoz7mccyaowzp.public.blob.vercel-storage.com', 2163],
  ['ug.alibaba.com', 2164],
  ['uk.indeed.com', 2165],
  ['ulogin.ru', 2166],
  ['unpkg.com', 2167],
  ['urs.pbs.org', 2168],
  ['vimeo.com', 2169],
  ['visitor-service.tealiumiq.com', 2170],
  ['visitor.pixplug.in', 2171],
  ['wb.amap.com', 2172],
  ['widget.usersnap.com', 2173],
  ['widgets.pinterest.com', 2174],
  ['wikipedia.org', 2175],
  ['wordpress.org', 2176],
  ['wse.api.here.com', 2177],
  ['www-api.ibm.com', 2178],
  ['www.ancestrycdn.com', 2179],
  ['www.bing.com', 2180],
  ['www.blogger.com', 2181],
  ['www.google-analytics.com', 2182],
  ['www.google.com', 2183],
  ['www.googleapis.com', 2184],
  ['www.googletagmanager.com', 2185],
  ['www.gstatic.com', 2186],
  ['www.meteoprog.ua', 2187],
  ['www.microsoft.com', 2188],
  ['www.paypal.com', 2189],
  ['www.recaptcha.net', 2190],
  ['www.reddit.com', 2191],
  ['www.roblox.com', 2192],
  ['www.st.com', 2193],
  ['www.yastat.net', 2194],
  ['www.yastatic.net', 2195],
  ['www.youtube.com', 2196],
  ['yandex.st', 2197],
  ['yastat.net', 2198],
  ['yastatic.net', 2199],
  ['yuedust.yuedu.126.net', 2200],
  ['yugiohmonstrosdeduelo.blogspot.com', 2201],
  ['zhike.help.360.cn', 2202],
  ['zhuanjia.sogou.com', 2203]
];

// Create servers for all domains
domains.forEach(([domain, port]) => {
  createServer(port, `https://${domain}`, domain, 'CSP Bypass Demo');
});
