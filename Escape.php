<?php declare(strict_types=1);

/**
 * A PHP implementation of OWASP Cross Site Scripting Prevention Cheat Sheet
 *
 * @package thisispiers\Xss
 * @url https://github.com/thisispiers/xss-escape
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
 * Last retrieved: 2021-11-04
 */

namespace thisispiers\Xss;

class Escape
{
    public static function encode(
        mixed $untrusted_data,
        string $format
    ): string {
        if (!is_string($untrusted_data)) {
            $untrusted_data = strval($untrusted_data);
        }
        $encoded_data = '';
        $untrusted_data_length = mb_strlen($untrusted_data, 'UTF-8');
        for ($i = 0; $i < $untrusted_data_length; $i++) {
            $char = mb_substr($untrusted_data, $i, 1, 'UTF-8');
            $ord = mb_ord($char);
            if (
                $ord >= 256
                || ($ord >= 48 && $ord <= 57)
                || ($ord >= 65 && $ord <= 90)
                || ($ord >= 97 && $ord <= 122)
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
     */
    public static function htmlBody(mixed $untrusted_data): string
    {
        if (!is_string($untrusted_data)) {
            $untrusted_data = strval($untrusted_data);
        }
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
     * Limit to whitelisted attributes:
     *     align, alink, alt, bgcolor, border, cellpadding, cellspacing, class,
     *     color, cols, colspan, coords, dir, face, height, hspace, ismap, lang,
     *     marginheight, marginwidth, multiple, nohref, noresize, noshade,
     *     nowrap, ref, rel, rev, rows, rowspan, scrolling, shape, span, summary,
     *     tabindex, title, usemap, valign, value, vlink, vspace, width.
     *
     * Except for alphanumeric characters, escape all characters with the
     * &#xHH; HTML entity format, including spaces
     *
     * Apply additional validation to href and src attributes
     */
    public const HTML_ATTR_WHITELIST = [
        'align', 'alink', 'alt', 'bgcolor', 'border', 'cellpadding',
        'cellspacing', 'class', 'color', 'cols', 'colspan', 'coords', 'dir',
        'face', 'height', 'hspace', 'ismap', 'lang', 'marginheight',
        'marginwidth', 'multiple', 'nohref', 'noresize', 'noshade', 'nowrap',
        'ref', 'rel', 'rev', 'rows', 'rowspan', 'scrolling', 'shape', 'span',
        'summary', 'tabindex', 'title', 'usemap', 'valign', 'value', 'vlink',
        'vspace', 'width',

        'href', 'src',
    ];
    public static function htmlAttr(
        string $attr,
        mixed $untrusted_data,
        bool $wrap = true
    ): string {
        $attr = mb_strtolower($attr);
        if (!in_array($attr, static::HTML_ATTR_WHITELIST, true)) {
            throw new \InvalidArgumentException('HTML attribute is not whitelisted');
        }
        if ($attr === 'href' || $attr === 'src') {
            $validated = static::validateUrl($untrusted_data);
        }

        $encoded_data = static::encode($untrusted_data, 'html');
        return $wrap ? ' ' . $attr . '="' . $encoded_data . '"' : $encoded_data;
    }

    /**
     * Context: Untrusted URL in a `src` or `href` attribute
     * e.g. <iframe src="UNTRUSTED URL" />
     * e.g. <a href="UNTRUSTED URL">link</a>
     *
     * Whitelist https URLs only
     *
     * Apply additional whitelisting, canonicalization and anti-virus checks
     * depending on the use-case
     */
    public static function validateUrl(mixed $untrusted_data): bool
    {
        if (!is_string($untrusted_data)) {
            $untrusted_data = strval($untrusted_data);
        }
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
     */
    public static function jsonInHtml(mixed $untrusted_data): string
    {
        $flags = \JSON_HEX_AMP|\JSON_HEX_TAG|\JSON_HEX_QUOT|\JSON_HEX_APOS|\JSON_THROW_ON_ERROR;
        return json_encode($untrusted_data, $flags) ?: '[]';
    }
}
