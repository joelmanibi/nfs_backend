'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { buildFileReceivedEmail, buildMailLogMeta, buildOTPEmail, formatFileSize } = require('../helpers/mailer');

test('buildOTPEmail includes otp and expiry', () => {
  const mail = buildOTPEmail({ email: 'user@example.com', otp: '123456', expiryMinutes: 10 });

  assert.equal(mail.to, 'user@example.com');
  assert.match(mail.text, /123456/);
  assert.match(mail.html, /10/);
});

test('buildFileReceivedEmail includes download code when file is protected', () => {
  const mail = buildFileReceivedEmail({
    to: 'dest@example.com',
    senderEmail: 'sender@example.com',
    originalName: 'secret.pdf',
    size: 2048,
    isProtected: true,
    downloadCode: 'ABCD-1234',
  });

  assert.equal(mail.to, 'dest@example.com');
  assert.match(mail.text, /ABCD-1234/);
  assert.match(mail.html, /ABCD-1234/);
});

test('buildFileReceivedEmail omits download code when file is not protected', () => {
  const mail = buildFileReceivedEmail({
    to: 'dest@example.com',
    senderEmail: 'sender@example.com',
    originalName: 'public.pdf',
    size: 512,
    isProtected: false,
    downloadCode: null,
  });

  assert.doesNotMatch(mail.text, /Code de téléchargement :/);
  assert.match(mail.text, /Aucun code de téléchargement/);
});

test('formatFileSize formats bytes and kilobytes', () => {
  assert.equal(formatFileSize(120), '120 octets');
  assert.equal(formatFileSize(2048), '2.0 KB');
});

test('buildMailLogMeta normalizes safe email logging metadata', () => {
  const meta = buildMailLogMeta({
    mailType: 'file_received_notification',
    to: 'DEST@Example.com ',
    subject: 'Nouveau fichier reçu',
    extra: {
      originalName: 'report.pdf',
      isProtected: true,
    },
  });

  assert.equal(meta.mailType, 'file_received_notification');
  assert.equal(meta.recipientEmail, 'dest@example.com');
  assert.equal(meta.subject, 'Nouveau fichier reçu');
  assert.equal(meta.originalName, 'report.pdf');
  assert.equal(meta.isProtected, true);
});