=== BiTek AI Security Guard ===
Contributors: bitek-security
Tags: comments, spam, security, ai, machine learning, toxic, malware, casino, adult content
Requires at least: 5.0
Tested up to: 6.3
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Advanced AI-powered comment security system that blocks spam, malicious, casino, and adult content using keyword filtering and HuggingFace AI models.

== Description ==

BiTek AI Security Guard is a comprehensive WordPress plugin that provides advanced protection against spam, malicious, and inappropriate comments using a dual-layer security approach:

**🛡️ Two-Layer Security System:**

1. **Keyword Filtering (Level 1)** - Fast, performance-optimized scanning using customizable keyword blacklists
2. **AI-Powered Detection (Level 2)** - Advanced machine learning models from HuggingFace for sophisticated content analysis

**🎯 What It Blocks:**
* Spam and promotional content
* Casino and gambling references
* Adult and pornographic content
* Malicious links and phishing attempts
* Cryptocurrency scams
* Weight loss and supplement spam
* Get-rich-quick schemes

**🚀 Key Features:**

* **Pre-trained AI Models**: Utilizes cybersecurity-focused models like Toxic BERT, Toxic Comment Model, and Hate Speech detectors
* **Customizable Keywords**: Add your own blocked terms and phrases
* **Real-time Scanning**: Comments are checked before database insertion
* **Comprehensive Logging**: Track all blocked attempts with detailed logs
* **Admin Dashboard**: Easy-to-use settings panel with API testing
* **Performance Optimized**: Keyword filtering provides fast initial screening
* **Security Focused**: All functions properly prefixed, sanitized inputs, and escaped outputs
* **Internationalization Ready**: Full i18n support with translation files

**🤖 Supported AI Models:**
* unitary/toxic-bert (Recommended)
* martin-ha/toxic-comment-model
* unitary/unbiased-toxic-roberta
* facebook/roberta-hate-speech-dynabench-r4-target

**🔧 Easy Setup:**
1. Install and activate the plugin
2. Get a free HuggingFace API key
3. Configure your settings
4. Your site is protected!

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/bitek-ai-security-guard` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress
3. Navigate to Settings → AI Security Guard to configure the plugin
4. Get a free API key from HuggingFace (https://huggingface.co/settings/tokens)
5. Enter your API key in the plugin settings
6. Configure your security preferences and save

== Frequently Asked Questions ==

= Do I need to pay for the AI models? =

No! HuggingFace provides free access to their inference API for moderate usage. You just need to create a free account and generate an API token.

= Will this slow down my website? =

The plugin is designed for performance. The keyword filtering happens first and is extremely fast. AI analysis only occurs if keywords don't catch the content, and it runs asynchronously during comment submission.

= Can I customize the blocked keywords? =

Yes! You can add, remove, or modify the keyword list in the admin settings. The plugin comes with a comprehensive default list covering common spam categories.

= What happens when a comment is blocked? =

The user sees a friendly error message explaining their comment contains inappropriate content. The comment is never saved to your database, and the attempt is logged for your review.

= Can I whitelist certain users? =

Yes, users with 'manage_options' capability (administrators) bypass all filtering automatically.

= Is the plugin GDPR compliant? =

Yes, the plugin only processes comment data during submission and doesn't store personal information beyond what WordPress normally logs.

== Screenshots ==

1. Admin settings page with AI and keyword configuration options
2. API connection test interface
3. Log statistics showing blocked comments and errors
4. Keyword management interface
5. User-friendly blocked comment message

== Changelog ==

= 1.0.0 =
* Initial release
* Dual-layer security system with keyword and AI filtering
* Support for multiple HuggingFace AI models
* Comprehensive logging system
* Full WordPress coding standards compliance
* Internationalization support
* Performance optimizations
* Security-focused architecture

== Upgrade Notice ==

= 1.0.0 =
Initial release of BiTek AI Security Guard. Install now to protect your WordPress site from spam and malicious comments.

== Privacy Policy ==

This plugin processes comment data to determine if content is appropriate for publication. The plugin:

* Sends comment text to HuggingFace API for analysis (only if AI filtering is enabled)
* Stores logs locally on your server (if logging is enabled)
* Does not collect or transmit personal user data beyond comment analysis
* Does not store comments that are blocked
* Respects user privacy and follows WordPress privacy guidelines

For HuggingFace's privacy policy, visit: https://huggingface.co/privacy

== Support ==

For support, feature requests, or bug reports, please visit:
* Plugin Support Forum
* GitHub Repository: https://github.com/bitek/ai-security-guard
* Documentation: https://bitek.dev/ai-security-guard-docs

== Credits ==

This plugin utilizes:
* HuggingFace Transformers and Inference API
* WordPress Coding Standards
* Modern PHP security practices