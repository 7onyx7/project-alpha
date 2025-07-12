/**************************************/
/*           legal.js                 */
/*      TERMS OF SERVICE & PRIVACY    */
/*         BANTRHAUS v1.0.0           */
/**************************************/

const termsOfService = `
# Terms of Service - Bantrhaus

**Effective Date:** ${new Date().toLocaleDateString()}
**Last Updated:** ${new Date().toLocaleDateString()}

## 1. Age Requirement
You must be at least 18 years old to use Bantrhaus. By using our service, you confirm that you are 18 or older.

## 2. Account Registration
- You must provide accurate information when creating an account
- You are responsible for maintaining the confidentiality of your account
- You may not create multiple accounts or share accounts with others
- We reserve the right to suspend or terminate accounts that violate these terms

## 3. Prohibited Behavior
You may not:
- Post illegal, harmful, threatening, abusive, or defamatory content
- Harass, stalk, or intimidate other users
- Share personal information of other users without consent
- Engage in spam, phishing, or other deceptive practices
- Impersonate others or provide false information
- Use the service for commercial purposes without authorization
- Attempt to hack, disrupt, or gain unauthorized access to our systems

## 4. Content Moderation
- We reserve the right to remove any content that violates these terms
- We may suspend or ban users who repeatedly violate our policies
- All messages may be subject to automated and human moderation
- We may preserve content for legal or safety purposes

## 5. Privacy
- We collect minimal personal information necessary for service operation
- We do not sell or share your personal information with third parties
- Messages may be stored temporarily for moderation purposes
- See our Privacy Policy for detailed information

## 6. Disclaimer
- The service is provided "as is" without warranties
- We are not responsible for user-generated content
- We do not guarantee uninterrupted service
- Users interact at their own risk

## 7. Termination
- You may delete your account at any time
- We may terminate accounts for violations of these terms
- Upon termination, we may retain certain information as required by law

## 8. Changes to Terms
We may update these terms at any time. Continued use of the service constitutes acceptance of updated terms.

## 9. Contact
For questions about these terms, contact us at: support@bantrhaus.com

By using Bantrhaus, you agree to these Terms of Service.
`;

const privacyPolicy = `
# Privacy Policy - Bantrhaus

**Effective Date:** ${new Date().toLocaleDateString()}
**Last Updated:** ${new Date().toLocaleDateString()}

## 1. Information We Collect
We collect minimal information necessary to provide our service:
- Username and email address (for registered users)
- Messages sent in chat rooms
- IP address and device information (for security)
- Usage statistics (anonymous)

## 2. How We Use Your Information
- To provide and improve our chat service
- To prevent abuse and ensure user safety
- To comply with legal requirements
- To send important service notifications

## 3. Information Sharing
We do not sell, trade, or share your personal information with third parties, except:
- When required by law
- To protect our rights or safety
- With your explicit consent

## 4. Data Security
- We use industry-standard encryption for data transmission
- Passwords are securely hashed and never stored in plain text
- We regularly update our security measures
- We limit access to personal information to authorized personnel only

## 5. Data Retention
- Messages are stored temporarily for moderation purposes
- Account information is retained while your account is active
- We may retain certain information as required by law
- You can request account deletion at any time

## 6. Your Rights
You have the right to:
- Access your personal information
- Correct inaccurate information
- Request deletion of your account
- Withdraw consent for data processing

## 7. Cookies
We use essential cookies for:
- User authentication
- Security protection (CSRF tokens)
- Service functionality

## 8. International Users
Our service is hosted in the United States. By using our service, you consent to the transfer of your information to the US.

## 9. Changes to This Policy
We may update this privacy policy. We will notify users of significant changes via email or service notification.

## 10. Contact Us
For privacy-related questions, contact us at: privacy@bantrhaus.com

This privacy policy is effective as of the date listed above.
`;

const communityGuidelines = `
# Community Guidelines - Bantrhaus

## Our Mission
Bantrhaus is a platform for respectful, anonymous conversations between consenting adults.

## Community Standards

### Respect Others
- Treat all users with respect and kindness
- Respect boundaries when someone wants to end a conversation
- No harassment, bullying, or intimidation
- Respect different viewpoints and backgrounds

### Stay Safe
- Never share personal information (real name, address, phone, etc.)
- Don't meet strangers from the platform in person
- Report suspicious or inappropriate behavior
- Trust your instincts - leave conversations that make you uncomfortable

### Keep It Legal
- No illegal activities or content
- No sharing of copyrighted material
- No fraud, scams, or deceptive practices
- Comply with local laws and regulations

### Content Guidelines
- No hate speech or discrimination
- No sexually explicit content
- No violence or threats
- No spam or excessive self-promotion
- No sharing of harmful or dangerous content

### Consequences
Violations may result in:
- Warning messages
- Temporary suspension
- Permanent ban from the platform
- Reporting to authorities (for illegal activities)

### Reporting
Help us maintain a safe community by reporting:
- Inappropriate messages or behavior
- Spam or abuse
- Technical issues
- Safety concerns

## Remember
You have the power to end any conversation at any time. If someone makes you uncomfortable, don't hesitate to leave the chat and report the behavior.

Together, we can create a positive, safe space for everyone.
`;

module.exports = {
  termsOfService,
  privacyPolicy,
  communityGuidelines
};
