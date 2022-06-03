# \thisispiers\Xss\Escape

A PHP implementation of [OWASP's Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

Released under LGPL v3.0. Requires PHP >= 7.1 and mbstring extension

Install with Composer `composer require thisispiers/xss-escape`

## Usage

Untrusted data should be encoded differently depending on context. This library provides a static method for each context.

### Text in HTML Body

i.e. `<span>UNTRUSTED DATA</span>`

```
htmlBody(mixed $untrusted_data): string
```

`$untrusted_data` is cast to string

### HTML in HTML body

i.e. `<div>UNTRUSTED HTML</div>`

Use a full HTML validator in this context, such as [HTML Purifier](https://github.com/ezyang/htmlpurifier) or [DOMPurify](https://github.com/cure53/DOMPurify)

### Safe HTML attributes

i.e. `<input type="text" name="field_name" value="UNTRUSTED DATA">`

```
htmlAttr(string $attr, mixed $untrusted_data, bool $wrap = true): string
```

`$attr` must be one of
- align
- alink
- alt
- bgcolor
- border
- cellpadding
- cellspacing
- class
- color
- cols
- colspan
- coords
- dir
- face
- height
- href (see [URLs](#URLs))
- hspace
- ismap
- lang
- marginheight
- marginwidth
- multiple
- nohref
- noresize
- noshade
- nowrap
- ref
- rel
- rev
- rows
- rowspan
- scrolling
- shape
- span
- src (see [URLs](#URLs))
- summary
- tabindex
- title
- usemap
- valign
- value
- vlink
- vspace
- width

`$untrusted_data` is cast to string

If `$wrap` is `true`, the returned string is prefixed by a space, the attribute name, an equal sign and wrapped in double quote marks i.e. `` value="ENCODED DATA"``.

### URLs

URLs in `src` or `href` HTML attributes i.e. `<iframe src="UNTRUSTED URL" />` or `<a href="UNTRUSTED URL">link</a>`

```
validateUrl(mixed $untrusted_data): bool
```

`$untrusted_data` is cast to string

Untrusted URLs are currently only checked to be HTTPS. This is a crude check to avoid becoming a full URL parsing library. It is highly recommended that you run more sophisticated validation on your untrusted URLs, such as rejecting URLs by hostname.

### JavaScript variables

i.e. `<script>var someValue='UNTRUSTED DATA';</script>` or `<script>someFunction('UNTRUSTED DATA');</script>`

```
jsVar(mixed $untrusted_data): string
```

`$untrusted_data` is cast to string

### CSS values

i.e. `<div style="width: UNTRUSTED DATA;">`

```
cssValue(mixed $untrusted_data): string
```

`$untrusted_data` is cast to string

### URL parameters

i.e. `<a href="/site/search?value=UNTRUSTED DATA">link</a>`

```
urlParam(mixed $untrusted_data): string
```

`$untrusted_data` is cast to string

### JSON in HTML

```
jsonInHtml(mixed $untrusted_data): string
```

`$untrusted_data` is cast to string

Output JSON inside a hidden element before calling `JSON.parse` e.g.
```
<div id="data" style="display:none"><?php echo \thisispiers\Xss\Escape::jsonInHtml($untrusted_data); ?></div>
<script>var data = JSON.parse(document.getElementById('data').textContent);</script>
```

## Contributing & Help

Don't expect frequent updates, but pull requests for security and performance improvements are welcome!

There is no guarantee this library complies with the latest OWASP cheat sheet recommendations. Create an issue if you think it's out of date, or start a pull request.

To save keystrokes, you might want to create an alias for this class
e.g. `class_alias('\\thisispiers\Xss\\Escape', '\\esc');`