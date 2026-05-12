/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-argument */
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import fs from 'node:fs';

const invoices = [
  {
    invoiceNumber: 'INV-2026-0606-011',
    recipient: 'Hiba Khadraoui',
    email: 'hkh304171@gmail.com',
    date: '2026-05-01',
    due: '2026-05-15',
    item: 'Ordinateur Portable',
    price: 2499.99,
    currency: 'USD',
    desc: 'Achat matériel informatique',
  },
  {
    invoiceNumber: 'INV-2026-0606-022',
    recipient: 'Hiba Khadraoui',
    email: 'hkh304171@gmail.com',
    date: '2026-05-02',
    due: '2026-05-16',
    item: 'Ecran 4K',
    price: 499,
    currency: 'USD',
    desc: 'Équipement bureau',
  },
  {
    invoiceNumber: 'INV-2026-0606-033',
    recipient: 'Hiba Khadraoui',
    email: 'hkh304171@gmail.com',
    date: '2026-05-03',
    due: '2026-05-17',
    item: 'Clavier Mécanique',
    price: 149.5,
    currency: 'USD',
    desc: 'Accessoires',
  },
  {
    invoiceNumber: 'INV-2026-0606-044',
    recipient: 'Hiba Khadraoui',
    email: 'hkh304171@gmail.com',
    date: '2026-05-04',
    due: '2026-05-18',
    item: 'Souris Sans Fil',
    price: 99,
    currency: 'USD',
    desc: 'Accessoires',
  },
  {
    invoiceNumber: 'INV-2026-0606-055',
    recipient: 'Hiba Khadraoui',
    email: 'hkh304171@gmail.com',
    date: '2026-05-05',
    due: '2026-05-19',
    item: 'Casque Réduction de Bruit',
    price: 349,
    currency: 'USD',
    desc: 'Matériel audio',
  },
];

for (const inv of invoices) {
  const doc = new jsPDF();

  // Header
  doc.setFontSize(22);
  doc.setTextColor(138, 34, 34);
  doc.text('Accountia Global Services', 14, 20);

  doc.setFontSize(16);
  doc.setTextColor(50);
  doc.text(`FACTURE #${inv.invoiceNumber}`, 14, 30);

  // Details
  doc.setFontSize(10);
  doc.setTextColor(100);
  doc.text(`Client: ${inv.recipient}`, 14, 45);
  doc.text(`Email: ${inv.email}`, 14, 51);
  doc.text(`Date: ${inv.date}`, 140, 45);
  doc.text(`Échéance: ${inv.due}`, 140, 51);

  // Table
  autoTable(doc, {
    startY: 60,
    head: [['Description', 'Quantité', 'Prix Unitaire', 'Total']],
    body: [
      [
        `${inv.item} - ${inv.desc}`,
        1,
        `${inv.price.toFixed(2)} ${inv.currency}`,
        `${inv.price.toFixed(2)} ${inv.currency}`,
      ],
    ],
    headStyles: { fillColor: [138, 34, 34] },
  });

  // Total
  const finalY = doc.lastAutoTable.finalY;
  doc.setFontSize(12);
  doc.setTextColor(0);
  doc.text(
    `Total à payer : ${inv.price.toFixed(2)} ${inv.currency}`,
    140,
    finalY + 15
  );

  // Footer
  doc.setFontSize(9);
  doc.setTextColor(150);
  doc.text('Merci pour votre confiance.', 14, finalY + 30);

  const fileName = `Facture_${inv.invoiceNumber}.pdf`;
  const buffer = Buffer.from(doc.output('arraybuffer'));
  fs.writeFileSync(fileName, buffer);
  console.log(`Generated: ${fileName}`);
}
