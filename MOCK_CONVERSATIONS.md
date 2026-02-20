# Mock Conversations for Swagger Testing

Use these payloads directly in `POST /honeypot`.
Keep the same `sessionId` for each turn inside one scenario.

## Scenario 1: Bank OTP + UPI + Link (8 turns)

### Turn 1
```json
{
  "sessionId": "mock-bank-otp-8turn-001",
  "message": {
    "sender": "scammer",
    "text": "URGENT: Your SBI account is blocked. Share OTP immediately."
  },
  "conversationHistory": [
    { "sender": "scammer", "text": "URGENT: Your SBI account is blocked. Share OTP immediately." }
  ],
  "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
}
```

### Turn 2
```json
{
  "sessionId": "mock-bank-otp-8turn-001",
  "message": {
    "sender": "scammer",
    "text": "I am from SBI fraud department, employee ID SBI-9921."
  },
  "conversationHistory": [
    { "sender": "scammer", "text": "URGENT: Your SBI account is blocked. Share OTP immediately." },
    { "sender": "user", "text": "which exact company are you from and your full department name" },
    { "sender": "scammer", "text": "I am from SBI fraud department, employee ID SBI-9921." }
  ],
  "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
}
```

### Turn 3
```json
{
  "sessionId": "mock-bank-otp-8turn-001",
  "message": {
    "sender": "scammer",
    "text": "Pay 1 rupee verification to securehelp@upi now."
  },
  "conversationHistory": [
    { "sender": "scammer", "text": "URGENT: Your SBI account is blocked. Share OTP immediately." },
    { "sender": "user", "text": "which exact company are you from and your full department name" },
    { "sender": "scammer", "text": "I am from SBI fraud department, employee ID SBI-9921." },
    { "sender": "user", "text": "please share your employee id and official designation" },
    { "sender": "scammer", "text": "Pay 1 rupee verification to securehelp@upi now." }
  ],
  "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
}
```

### Turn 4
```json
{
  "sessionId": "mock-bank-otp-8turn-001",
  "message": {
    "sender": "scammer",
    "text": "Call my direct number +91-9876543210."
  },
  "conversationHistory": [
    { "sender": "scammer", "text": "URGENT: Your SBI account is blocked. Share OTP immediately." },
    { "sender": "user", "text": "which exact company are you from and your full department name" },
    { "sender": "scammer", "text": "I am from SBI fraud department, employee ID SBI-9921." },
    { "sender": "user", "text": "please share your employee id and official designation" },
    { "sender": "scammer", "text": "Pay 1 rupee verification to securehelp@upi now." },
    { "sender": "user", "text": "why are you asking otp if you are bank side please explain" },
    { "sender": "scammer", "text": "Call my direct number +91-9876543210." }
  ],
  "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
}
```

### Turn 5
```json
{
  "sessionId": "mock-bank-otp-8turn-001",
  "message": {
    "sender": "scammer",
    "text": "Use secure-sbi-verification-help.in to update KYC now."
  },
  "conversationHistory": [
    { "sender": "scammer", "text": "URGENT: Your SBI account is blocked. Share OTP immediately." },
    { "sender": "user", "text": "which exact company are you from and your full department name" },
    { "sender": "scammer", "text": "I am from SBI fraud department, employee ID SBI-9921." },
    { "sender": "user", "text": "please share your employee id and official designation" },
    { "sender": "scammer", "text": "Pay 1 rupee verification to securehelp@upi now." },
    { "sender": "user", "text": "why are you asking otp if you are bank side please explain" },
    { "sender": "scammer", "text": "Call my direct number +91-9876543210." },
    { "sender": "user", "text": "which official website should i verify now please send full url" },
    { "sender": "scammer", "text": "Use secure-sbi-verification-help.in to update KYC now." }
  ],
  "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
}
```

### Turn 6
```json
{
  "sessionId": "mock-bank-otp-8turn-001",
  "message": {
    "sender": "scammer",
    "text": "Case ID REF91X2A, complete before legal action."
  },
  "conversationHistory": [
    { "sender": "scammer", "text": "URGENT: Your SBI account is blocked. Share OTP immediately." },
    { "sender": "user", "text": "which exact company are you from and your full department name" },
    { "sender": "scammer", "text": "I am from SBI fraud department, employee ID SBI-9921." },
    { "sender": "user", "text": "please share your employee id and official designation" },
    { "sender": "scammer", "text": "Pay 1 rupee verification to securehelp@upi now." },
    { "sender": "user", "text": "why are you asking otp if you are bank side please explain" },
    { "sender": "scammer", "text": "Call my direct number +91-9876543210." },
    { "sender": "user", "text": "which official website should i verify now please send full url" },
    { "sender": "scammer", "text": "Use secure-sbi-verification-help.in to update KYC now." },
    { "sender": "user", "text": "please share case id or complaint reference number again" },
    { "sender": "scammer", "text": "Case ID REF91X2A, complete before legal action." }
  ],
  "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
}
```

### Turn 7
```json
{
  "sessionId": "mock-bank-otp-8turn-001",
  "message": {
    "sender": "scammer",
    "text": "Mail us at sbi.alertdesk@securemail-check.com for closure."
  },
  "conversationHistory": [
    { "sender": "scammer", "text": "URGENT: Your SBI account is blocked. Share OTP immediately." },
    { "sender": "user", "text": "which exact company are you from and your full department name" },
    { "sender": "scammer", "text": "I am from SBI fraud department, employee ID SBI-9921." },
    { "sender": "user", "text": "please share your employee id and official designation" },
    { "sender": "scammer", "text": "Pay 1 rupee verification to securehelp@upi now." },
    { "sender": "user", "text": "why are you asking otp if you are bank side please explain" },
    { "sender": "scammer", "text": "Call my direct number +91-9876543210." },
    { "sender": "user", "text": "which official website should i verify now please send full url" },
    { "sender": "scammer", "text": "Use secure-sbi-verification-help.in to update KYC now." },
    { "sender": "user", "text": "please share case id or complaint reference number again" },
    { "sender": "scammer", "text": "Case ID REF91X2A, complete before legal action." },
    { "sender": "user", "text": "can you share your official email so my son can verify" },
    { "sender": "scammer", "text": "Mail us at sbi.alertdesk@securemail-check.com for closure." }
  ],
  "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
}
```

### Turn 8
```json
{
  "sessionId": "mock-bank-otp-8turn-001",
  "message": {
    "sender": "scammer",
    "text": "Final warning: do it now."
  },
  "conversationHistory": [
    { "sender": "scammer", "text": "URGENT: Your SBI account is blocked. Share OTP immediately." },
    { "sender": "user", "text": "which exact company are you from and your full department name" },
    { "sender": "scammer", "text": "I am from SBI fraud department, employee ID SBI-9921." },
    { "sender": "user", "text": "please share your employee id and official designation" },
    { "sender": "scammer", "text": "Pay 1 rupee verification to securehelp@upi now." },
    { "sender": "user", "text": "why are you asking otp if you are bank side please explain" },
    { "sender": "scammer", "text": "Call my direct number +91-9876543210." },
    { "sender": "user", "text": "which official website should i verify now please send full url" },
    { "sender": "scammer", "text": "Use secure-sbi-verification-help.in to update KYC now." },
    { "sender": "user", "text": "please share case id or complaint reference number again" },
    { "sender": "scammer", "text": "Case ID REF91X2A, complete before legal action." },
    { "sender": "user", "text": "can you share your official email so my son can verify" },
    { "sender": "scammer", "text": "Mail us at sbi.alertdesk@securemail-check.com for closure." },
    { "sender": "user", "text": "what is your office address and branch location" },
    { "sender": "scammer", "text": "Final warning: do it now." }
  ],
  "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
}
```

## Scenario 2: UPI Cashback Scam

```json
{
  "sessionId": "mock-upi-cashback-001",
  "message": {
    "sender": "scammer",
    "text": "Congratulations! You won cashback 4999. Approve collect request and send to cashback.bonus@upi now."
  },
  "conversationHistory": [
    { "sender": "scammer", "text": "Congratulations! You won cashback 4999. Approve collect request and send to cashback.bonus@upi now." }
  ],
  "metadata": { "channel": "WhatsApp", "language": "English", "locale": "IN" }
}
```

## Scenario 3: Phishing Product Offer

```json
{
  "sessionId": "mock-phishing-offer-001",
  "message": {
    "sender": "scammer",
    "text": "Claim free iPhone now at http://amaz0n-offer-secure-gift.in/claim?id=9988 before offer ends."
  },
  "conversationHistory": [
    { "sender": "scammer", "text": "Claim free iPhone now at http://amaz0n-offer-secure-gift.in/claim?id=9988 before offer ends." }
  ],
  "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
}
```

## Scenario 4: Courier/Customs Hold

```json
{
  "sessionId": "mock-customs-001",
  "message": {
    "sender": "scammer",
    "text": "Parcel held by customs. Case REF-AB12345. Pay duty to clearpay@upi. Support: customs.helpdesk@quickmail-secure.com"
  },
  "conversationHistory": [
    { "sender": "scammer", "text": "Parcel held by customs. Case REF-AB12345. Pay duty to clearpay@upi. Support: customs.helpdesk@quickmail-secure.com" }
  ],
  "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
}
```

## Scenario 5: Insurance Policy Update Scam

```json
{
  "sessionId": "mock-policy-001",
  "message": {
    "sender": "scammer",
    "text": "Policy POL778811 is expiring today. Send renewal fee to lifecover.help@upi and confirm at +91 9123456789."
  },
  "conversationHistory": [
    { "sender": "scammer", "text": "Policy POL778811 is expiring today. Send renewal fee to lifecover.help@upi and confirm at +91 9123456789." }
  ],
  "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
}
```

## Scenario 6: Refund + Order ID Scam

```json
{
  "sessionId": "mock-refund-order-001",
  "message": {
    "sender": "scammer",
    "text": "Refund pending for ORDERAZ99881. Verify immediately at flipkart-refund-center-help.com and share OTP."
  },
  "conversationHistory": [
    { "sender": "scammer", "text": "Refund pending for ORDERAZ99881. Verify immediately at flipkart-refund-center-help.com and share OTP." }
  ],
  "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
}
```

## Scenario 7: Remote Access App Scam

```json
{
  "sessionId": "mock-remote-001",
  "message": {
    "sender": "scammer",
    "text": "Your device is hacked. Install AnyDesk now and share the code for account protection."
  },
  "conversationHistory": [
    { "sender": "scammer", "text": "Your device is hacked. Install AnyDesk now and share the code for account protection." }
  ],
  "metadata": { "channel": "Call-Chat", "language": "English", "locale": "IN" }
}
```

## Scenario 8: Income Tax Penalty Scam

```json
{
  "sessionId": "mock-tax-001",
  "message": {
    "sender": "scammer",
    "text": "Income tax legal notice issued. Pay penalty now to taxpaydesk@upi or account 123456789012 IFSC SBIN0001234."
  },
  "conversationHistory": [
    { "sender": "scammer", "text": "Income tax legal notice issued. Pay penalty now to taxpaydesk@upi or account 123456789012 IFSC SBIN0001234." }
  ],
  "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
}
```

## Scenario 9: SIM KYC Re-verification Scam

```json
{
  "sessionId": "mock-sim-kyc-001",
  "message": {
    "sender": "scammer",
    "text": "SIM KYC failed. Number will be deactivated in 30 minutes. Verify now at airtel-kyc-fastcheck.in."
  },
  "conversationHistory": [
    { "sender": "scammer", "text": "SIM KYC failed. Number will be deactivated in 30 minutes. Verify now at airtel-kyc-fastcheck.in." }
  ],
  "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
}
```

## Scenario 10: Job Offer Advance Fee Scam

```json
{
  "sessionId": "mock-job-001",
  "message": {
    "sender": "scammer",
    "text": "Job confirmed. Pay documentation fee to hr.fastoffer@upi and message your details to +91-9988776655."
  },
  "conversationHistory": [
    { "sender": "scammer", "text": "Job confirmed. Pay documentation fee to hr.fastoffer@upi and message your details to +91-9988776655." }
  ],
  "metadata": { "channel": "WhatsApp", "language": "English", "locale": "IN" }
}
```

## Scenario 11: Loan Processing Scam

```json
{
  "sessionId": "mock-loan-001",
  "message": {
    "sender": "scammer",
    "text": "Instant loan approved. Process fee to loan.fast@upi. Case LNC4499. Share OTP to disburse."
  },
  "conversationHistory": [
    { "sender": "scammer", "text": "Instant loan approved. Process fee to loan.fast@upi. Case LNC4499. Share OTP to disburse." }
  ],
  "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
}
```

## Scenario 12: Non-Scam Baseline

```json
{
  "sessionId": "mock-nonscam-001",
  "message": {
    "sender": "scammer",
    "text": "Hi, this is a reminder for your dentist appointment tomorrow at 5 PM."
  },
  "conversationHistory": [
    { "sender": "scammer", "text": "Hi, this is a reminder for your dentist appointment tomorrow at 5 PM." }
  ],
  "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
}
```
