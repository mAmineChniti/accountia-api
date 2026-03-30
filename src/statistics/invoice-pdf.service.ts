import { Injectable } from '@nestjs/common';
import * as puppeteer from 'puppeteer';
import * as handlebars from 'handlebars';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class InvoicePdfService {
    constructor() {
        handlebars.registerHelper('formatCurrency', (value: number) => {
            return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(value);
        });
    }

    async generatePdf(data: any): Promise<Buffer> {
        const templatePath = path.join(process.cwd(), 'src/statistics/templates/invoice-base.hbs');
        const templateSource = fs.readFileSync(templatePath, 'utf8');
        const template = handlebars.compile(templateSource);
        const html = template(data);

        const browser = await puppeteer.launch({
            headless: true,
            args: ['--no-sandbox', '--disable-setuid-sandbox'],
        });

        const page = await browser.newPage();
        await page.setContent(html, { waitUntil: 'networkidle0' });

        const pdf = await page.pdf({
            format: 'A4',
            printBackground: true,
            margin: { top: '0', right: '0', bottom: '0', left: '0' },
        });

        await browser.close();
        return Buffer.from(pdf);
    }
}
