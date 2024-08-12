<?php declare(strict_types=1);

/**
 * A PHP implementation of OWASP Cross Site Scripting Prevention Cheat Sheet
 *
 * @package thisispiers\Xss
 * @link https://github.com/thisispiers/xss-escape
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
 * Last retrieved: 2024-08-20
 */

namespace thisispiers\Xss;

class Escape
{
    /**
     * @throws \InvalidArgumentException if data cannot be converted to a string
     */
    public static function encode(
        mixed $untrusted_data,
        string $format
    ): string {
        $untrusted_data = static::stringOrThrow($untrusted_data);
        $encoded_data = '';
        $untrusted_data_length = mb_strlen($untrusted_data, 'UTF-8');
        for ($i = 0; $i < $untrusted_data_length; $i++) {
            $char = mb_substr($untrusted_data, $i, 1, 'UTF-8');
            $ord = mb_ord($char);
            if (
                $ord >= 256 // non-ASCII
                || ($ord >= 48 && $ord <= 57) // 0-9
                || ($ord >= 65 && $ord <= 90) // A-Z
                || ($ord >= 97 && $ord <= 122) // a-z
            ) {
                $encoded_data .= $char;
            } else {
                $hex = mb_strtoupper(dechex($ord));
                if ($format === 'html') {
                    $encoded_data .= '&#x' . $hex . ';';
                } else if ($format === 'unicode') {
                    $encoded_data .= '\\u{' . $hex . '}';
                } else if ($format === 'css') {
                    $hex = str_pad($hex, 6, '0', \STR_PAD_LEFT);
                    $encoded_data .= '\\' . $hex;
                } else if ($format === 'url') {
                    $encoded_data .= '%' . $hex;
                }
            }
        }

        return $encoded_data;
    }

    /**
     * Context: Text in HTML body
     * e.g. <span>UNTRUSTED DATA</span>
     *
     * Encode entities:
     *     & to &amp;
     *     < to &lt;
     *     > to &gt;
     *     " to &quot;
     *     ' to &#x27;
     *
     * @throws \InvalidArgumentException if data cannot be converted to a string
     */
    public static function htmlBody(mixed $untrusted_data): string
    {
        $untrusted_data = static::stringOrThrow($untrusted_data);
        $untrusted_data = str_replace('&', '&amp;',  $untrusted_data);
        $untrusted_data = str_replace('<', '&lt;',   $untrusted_data);
        $untrusted_data = str_replace('>', '&gt;',   $untrusted_data);
        $untrusted_data = str_replace('"', '&quot;', $untrusted_data);
        $untrusted_data = str_replace("'", '&#x27;', $untrusted_data);

        return $untrusted_data;
    }

    /**
     * Context: HTML in HTML body
     * e.g. <div>UNTRUSTED HTML</div>
     *
     * HTML Validation (i.e. PHP HTML Purifier)
     */
    /*public static function validate_html($untrusted_html)
    {

    }*/

    /**
     * Context: Safe HTML attributes
     * e.g. <input type="text" name="field_name" value="UNTRUSTED DATA">
     *
     * Limit to safe attributes
     * @link https://github.com/cure53/DOMPurify/blob/main/src/attrs.js
     *
     * Except for alphanumeric characters, escape all characters with the
     * &#xHH; HTML entity format, including spaces
     *
     * Apply additional validation to href and src attributes
     *
     * @throws \InvalidArgumentException if the attribute is not considered safe
     * @throws \InvalidArgumentException if data cannot be converted to a string
     */
    public const HTML_ATTRS_ALLOWED = [
        'accept', 'action', 'align', 'alt', 'autocapitalize', 'autocomplete',
        'autopictureinpicture', 'autoplay', 'background', 'bgcolor', 'border',
        'capture', 'cellpadding', 'cellspacing', 'checked', 'cite', 'class',
        'clear', 'color', 'cols', 'colspan', 'controls', 'controlslist',
        'coords', 'crossorigin', 'datetime', 'decoding', 'default', 'dir',
        'disabled', 'disablepictureinpicture', 'disableremoteplayback',
        'download', 'draggable', 'enctype', 'enterkeyhint', 'face', 'for',
        'headers', 'height', 'hidden', 'high', 'href', 'hreflang', 'id',
        'inputmode', 'integrity', 'ismap', 'kind', 'label', 'lang', 'list',
        'loading', 'loop', 'low', 'max', 'maxlength', 'media', 'method', 'min',
        'minlength', 'multiple', 'muted', 'name', 'nonce', 'noshade',
        'novalidate', 'nowrap', 'open', 'optimum', 'pattern', 'placeholder',
        'playsinline', 'popover', 'popovertarget', 'popovertargetaction',
        'poster', 'preload', 'pubdate', 'radiogroup', 'readonly', 'rel',
        'required', 'rev', 'reversed', 'role', 'rows', 'rowspan', 'spellcheck',
        'scope', 'selected', 'shape', 'size', 'sizes', 'span', 'srclang',
        'start', 'src', 'srcset', 'step', 'style', 'summary', 'tabindex',
        'title', 'translate', 'type', 'usemap', 'valign', 'value', 'width',
        'wrap', 'xmlns', 'slot',

        'href', 'src',
    ];
    public static function htmlAttr(
        string $attr,
        mixed $untrusted_data,
        bool $wrap = true
    ): string {
        $attr = mb_strtolower($attr);
        if (!in_array($attr, static::HTML_ATTRS_ALLOWED, true)) {
            throw new \InvalidArgumentException('HTML attribute is not allowed');
        }
        $untrusted_data = static::stringOrThrow($untrusted_data);
        if ($attr === 'href' || $attr === 'src') {
            $validated = static::validateUrl($untrusted_data);
        }

        $encoded_data = static::htmlAttrValue($untrusted_data);
        return $wrap ? ' ' . $attr . '="' . $encoded_data . '"' : $encoded_data;
    }

    /**
     * Context: HTML attribute values
     * e.g. <div class="class1 class2 UNTRUSTED DATA">
     *
     * @throws \InvalidArgumentException if data cannot be converted to a string
     */
    public static function htmlAttrValue(mixed $untrusted_data): string
    {
        return static::encode($untrusted_data, 'html');
    }

    /**
     * Context: Untrusted URL in a `src` or `href` attribute
     * e.g. <iframe src="UNTRUSTED URL" />
     * e.g. <a href="UNTRUSTED URL">link</a>
     *
     * Allow https URLs only
     *
     * Apply additional validation, canonicalization and anti-virus checks
     * depending on the use-case
     *
     * @throws \InvalidArgumentException if data cannot be converted to a string
     * @throws \InvalidArgumentException if the URL protocol is not HTTPS
     */
    public static function validateUrl(mixed $untrusted_data): bool
    {
        $untrusted_data = static::stringOrThrow($untrusted_data);
        $protocol = mb_substr($untrusted_data, 0, 8);
        if ($protocol !== 'https://') {
            throw new \InvalidArgumentException('URL is not HTTPS');
        }

        return true;
    }

    /**
     * Context: JavaScript variable
     * e.g. <script>var someValue='UNTRUSTED DATA';</script>
     * e.g. <script>someFunction('UNTRUSTED DATA');</script>
     *
     * Do not use this when outputting JSON in HTML. Instead, use the dedicated
     * jsonInHtml method
     *
     * Ensure JavaScript variables are quoted
     *
     * Except for alphanumeric characters, escape all characters with the
     * \uXXXX unicode escaping format
     *
     * Avoid backslash encoding
     *
     * @throws \InvalidArgumentException if data cannot be converted to a string
     */
    public static function jsVar(mixed $untrusted_data): string
    {
        $encoded_data = static::encode($untrusted_data, 'unicode');
        return $encoded_data;
    }

    /**
     * Context: CSS value
     * e.g. <div style="width: UNTRUSTED DATA;">
     *
     * CSS escaping supports \XX and \XXXXXX. Zero-pad to 6 characters
     *
     * @throws \InvalidArgumentException if data cannot be converted to a string
     */
    public static function cssValue(mixed $untrusted_data): string
    {
        $encoded_data = static::encode($untrusted_data, 'css');
        return $encoded_data;
    }

    /**
     * Context: URL parameter
     * e.g. <a href="/site/search?value=UNTRUSTED DATA">link</a>
     *
     * Except for alphanumeric characters, escape all characters with the
     * %HH escaping format
     *
     * If using URL in an href or other HTML attribute, remember to also encode
     * using htmlAttr()
     *
     * @throws \InvalidArgumentException if data cannot be converted to a string
     */
    public static function urlParam(mixed $untrusted_data): string
    {
        $encoded_data = static::encode($untrusted_data, 'url');
        return $encoded_data;
    }

    /**
     * Context: JSON in HTML
     * e.g. <div id="data" style="display:none"><?php echo \thisispiers\Xss\Escape::jsonInHtml($untrusted_data); ?></div>
     * e.g. var data = JSON.parse(document.getElementById('data').textContent);
     *
     * Encode entities: & < > " '
     *
     * Output JSON inside a hidden element before calling JSON.parse(el.textContent)
     *
     * @param mixed $untrusted_data
     * @throws \JsonException if there was an error during encoding
     */
    public static function jsonInHtml(mixed $untrusted_data): string
    {
        $flags = \JSON_HEX_AMP|\JSON_HEX_TAG|\JSON_HEX_QUOT|\JSON_HEX_APOS|\JSON_THROW_ON_ERROR;
        return json_encode($untrusted_data, $flags) ?: '[]';
    }

    /**
     * @throws \InvalidArgumentException if the variable cannot be converted to
     *                                   a string
     */
    protected static function stringOrThrow(mixed $var): string
    {
        if (
            is_string($var)
            || $var instanceof \Stringable
            || is_int($var)
            || is_float($var)
            || $var === null
        ) {
            return strval($var);
        } else {
            $msg = 'Variable must be a string or convertible to a string';
            throw new \InvalidArgumentException($msg);
        }
    }

}
