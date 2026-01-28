const fs = require("fs");
const puppeteer = require("puppeteer");
async function extractDOM(url, outputFile) {
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });
  const page = await browser.newPage();
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 60000 });
  const domTree = await page.evaluate(() => {
    function traverse(node) {
      return {
        tag: node.tagName,
        children: [...node.children].map(traverse),
      };
    }
    return {
      title: document.title,
      dom: traverse(document.body)
    };
  });
  await page.screenshot({ path: outputFile.replace('.json', '.png'), fullPage: true });
  fs.writeFileSync(outputFile, JSON.stringify(domTree, null, 2));
  await browser.close();
}
const url = process.argv[2];
const outputFile = process.argv[3];
extractDOM(url, outputFile);