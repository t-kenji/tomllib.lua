---
--  Lua TOML library.
--  porting from python module tomllib.
--
--  @module     tomllib
--  @author     t-kenji <protect.2501@gmail.com>
--  @license    MIT
--  @copyright  2023-2024 t-kenji

local _M = {
    _VERSION = '0.3.0',
    toml_spec = '1.0.0', -- Supported toml version
}

local pprint = require('pprint')
local char, byte, find, match, sub, gsub, rep, format =
    string.char, string.byte, string.find, string.match, string.sub, string.gsub, string.rep,
    string.format
local insert = table.insert

-- Neither of these sets include quotation mark or backslash. They are
-- currently handled as separate cases in the parser functions.
local ILLEGAL_BASIC_STR_CHARS = '[\001-\008\010-\031\127]'
local ILLEGAL_MULTILINE_BASIC_STR_CHARS = '[\001-\008\011-\031\127]'

local ILLEGAL_LITERAL_STR_CHARS = ILLEGAL_BASIC_STR_CHARS
local ILLEGAL_MULTILINE_LITERAL_STR_CHARS = ILLEGAL_MULTILINE_BASIC_STR_CHARS

local ILLEGAL_COMMENT_CHARS = ILLEGAL_BASIC_STR_CHARS
local ILLEGAL_HEXDIGIT_CHARS = '[^%x]'

local TOML_WS = '[\009\032]'                     -- '\t' and ' '
local TOML_WS_AND_NEWLINE = '[\009\032\010]'     -- '\t', ' ' and '\n'
local BARE_KEY_CHARS = '[%w\045\095]'            -- 'a' to 'z', 'A' to 'Z', '0' to '9', '_' and '-'
local KEY_INITIAL_CHARS = '[%w\045\095\034\039]' -- BARE_KEY_CHARS, '"' and "'"

local BASIC_STR_ESCAPE_REPLACEMENTS = {
    ['\\b']  = 'b',  -- backspace
    ['\\t']  = 't',  -- tab
    ['\\n']  = 'n',  -- linefeed
    ['\\f']  = 'f',  -- from feed
    ['\\r']  = 'r',  -- carriage return
    ['\\"']  = '"',  -- quote
    ['\\\\'] = '\\', -- backslash
}


local function contains(t, x)
    -- array
    for _, v in pairs(t) do
        if v == x then
            return true
        end
    end
    -- dict
    if t[x] then
        return true
    end
    return false
end

local function combine(...)
    local args = {...}
    local t = {}
    for _, arg in ipairs(args) do
        for _, v in ipairs(arg) do
            insert(t, v)
        end
    end
    return t
end

local function startswith(s, x, pos)
    return find(s, '^' .. x, pos)
end

local function torawstring(s)
    return gsub(s, '([\n\t"])', '\\%1')
end

local function iterable(s)
    local pos = 0
    local len = #s
    return function ()
        pos = pos + 1
        if pos > len then
            return nil
        else
            return pos, char(byte(s, pos))
        end
    end, {}, nil
end

local function shallow_copy(t, i, j)
    local first, last
    if j then
        first = i
        last = j
    elseif i then
        first = i
        last = #t
    else
        first = 1
        last = #t
    end
    first = first < 0 and #t - first - 1 or first
    last  = last < 0 and #t - last - 2 or last

    local o = {}
    for idx=first, last do
        insert(o, t[idx])
    end
    return o
end

local function get_or_create_nest(t, key, opts)
    opts = opts or {}
    local access_lists = opts.access_lists or true
    local cont = t
    for _, k in ipairs(key) do
        if not cont[k] then
            cont[k] = {}
        end
        cont = cont[k]
        if access_lists and #cont > 0 then
            cont = cont[#cont]
        end
        if type(cont) ~= 'table' then
            error('There is no nest behind this key')
        end
    end
    return cont
end

local function append_nest_to_list(t, key)
    local cont = get_or_create_nest(t, shallow_copy(key, 1, -1))
    local last_key = key[#key]
    if contains(cont, last_key) then
        local list = cont[last_key]
        if type(list) ~= 'table' then
            error('An object other than list found bihind this key')
        end
        insert(list, {})
    else
        cont[last_key] = {{}}
    end
end

local function is_unicode_scalar_value(codepoint)
    return (0 <= codepoint and codepoint <= 55295) or (57344 <= codepoint and codepoint <= 1114111)
end

-- Return a `error` where error message is suffixed with coordinates in source.
local function suffixed_err(src, pos, msg)
    local function coord_repr(src, pos)
        local up_to = sub(src, 1, pos)
        if pos >= #src then
            return 'end of document'
        end
        local _, line = gsub(up_to, '\n', '')
        line = line + 1
        local column
        if line == 1 then
            column = pos + 1
        else
            local last_newline = find(up_to, '\n[^\n]*$')
            column = pos - last_newline
        end
        return 'line ' .. line .. ', column ' .. column
    end
    error(msg .. ' (at ' .. coord_repr(src, pos) .. ')')
end

local function skip_chars(src, pos, chars)
    local len = #src
    while pos <= len do
        local c = char(byte(src, pos))
        if not find(c, chars) then
            return pos, c
        end
        pos = pos + 1
    end
    return nil
end

local function skip_until(src, pos, expect, opts)
    local error_on = opts.error_on
    local error_on_eof = opts.error_on_eof
    local new_pos = find(src, expect, pos)
    if not new_pos then
        new_pos = #src
        if error_on_eof then
            suffixed_err(src, new_pos, 'Expected ' .. torawstring(expect))
        end
    end

    local isdisjoint = not find(sub(src, pos, new_pos - 1), error_on)
    if not isdisjoint then
        while not find(char(byte(src, pos)), error_on) do
            pos = pos + 1
        end
        suffixed_err(src, pos, 'Found invalid character ' .. torawstring(char(byte(src, pos))))
    end
    return new_pos
end

local function skip_comment(src, pos)
    local c = char(byte(src, pos))
    if c == '#' then
        return skip_until(src, pos + 1, '\n', {error_on=ILLEGAL_COMMENT_CHARS, error_on_eof=false})
    end
    return pos
end

local function skip_comments_and_array_ws(src, pos)
    while true do
        local pos_before_skip = pos
        pos = skip_chars(src, pos, TOML_WS_AND_NEWLINE)
        pos = skip_comment(src, pos)
        if pos == pos_before_skip then
            return pos
        end
    end
end

local function parse_hex_char(src, pos, hex_len)
    local hex_str = sub(src, pos, pos + hex_len - 1)
    if #hex_str ~= hex_len or find(hex_str, ILLEGAL_HEXDIGIT_CHARS) then
        suffixed_err(src, pos, 'Invalid hex value')
    end
    pos = pos + hex_len
    local hex_int = tonumber(hex_str, 16)
    if not is_unicode_scalar_value(hex_int) then
        suffixed_err(src, pos, 'Escaped character is not a Unicode scalar value')
    end
    return pos, char(hex_int)
end

local function parse_basic_str_escape(src, pos, opts)
    opts = opts or {}
    local multiline = opts.multiline or false
    local escape_id = sub(src, pos, pos + 1)
    pos = pos + 2
    if multiline and contains({'\\ ', '\\\t', '\\\n'}, escape_id) then
        -- Skip whitespace untile next non-whitespace character or end of
        -- the doc. Error if non-whitespace is found before newline.
        if escape_id ~= '\\\n' then
            pos = skip_chars(src, pos, TOML_WS)
            local c = char(byte(src, pos))
            if c ~= '\n' then
                suffixed_err(src, pos, "Unescaped '\\' in a string")
            end
            pos = pos + 1
        end
        pos = skip_chars(src, pos, TOML_WS_AND_NEWLINE)
        return pos, ''
    elseif escape_id == '\\u' then
        return parse_hex_char(src, pos, 4)
    elseif escape_id == '\\U' then
        return parse_hex_char(src, pos, 8)
    end
    local escaped_char = BASIC_STR_ESCAPE_REPLACEMENTS[escape_id]
    if not escaped_char then
        suffixed_err(src, pos, "Unescaped '\\' in a string")
    end
    return pos, escaped_char
end

local function parse_basic_str_escape_multiline(src, pos)
    return parse_basic_str_escape(src, pos, {multiline=true})
end

local function parse_basic_str(src, pos, opts)
    local multiline = opts.multiline or false
    local error_on, parse_escapes
    if multiline then
        error_on = ILLEGAL_MULTILINE_BASIC_STR_CHARS
        parse_escapes = parse_basic_str_escape_multiline
    else
        error_on = ILLEGAL_BASIC_STR_CHARS
        parse_escapes = parse_basic_str_escape
    end
    local result = ''
    local start_pos = pos
    local len = #src
    while pos <= len do
        local c = char(byte(src, pos))
        if c == '"' then
            if not multiline then
                return pos + 1, result .. sub(src, start_pos, pos - 1)
            elseif startswith(src, '"""', pos) then
                return pos + 3, result .. sub(src, start_pos, pos - 1)
            end
            pos = pos + 1
        elseif c == '\\' then
            result = result .. sub(src, start_pos, pos - 1)
            local parsed_escape
            pos, parsed_escape = parse_escapes(src, pos)
            result = result .. parsed_escape
            start_pos = pos
        elseif find(c, error_on) then
            suffixed_err(src, pos, 'Illegal character ' .. torawstring(c))
        else
            pos = pos + 1
        end
    end
    suffixed_err(src, pos, 'Unterminated string')
end

local function parse_multiline_str(src, pos, opts)
    local literal = opts.literal
    pos = pos + 3
    if startswith(src, '\n', pos) then
        pos = pos + 1
    end

    local delim, result
    if literal then
        delim = "'"
        local end_pos = skip_until(src, pos, "'''", {error_on=ILLEGAL_MULTILINE_LITERAL_STR_CHARS,
                                   error_on_eof=true})
        result = sub(src, pos, end_pos - 1)
        pos = end_pos + 3
    else
        delim = '"'
        pos, result = parse_basic_str(src, pos, {multiline=true})
    end

    -- Add at maximum two extra apostrophes/quotes if the end sequence
    -- is 4 or 5 chars long instead of just 3.
    if not startswith(src, delim, pos) then
        return pos, result
    end
    pos = pos + 1
    if not startswith(src, delim, pos) then
        return pos, result .. delim
    end
    pos = pos + 1
    return pos, result .. rep(delim, 2)
end

local function parse_literal_str(src, pos)
    pos = pos + 1 -- Skip starting apostrophe
    local start_pos = pos
    pos = skip_until(src, pos, "'", {error_on=ILLEGAL_LITERAL_STR_CHARS, error_on_eof=true})
    return pos + 1, sub(src, start_pos, pos - 1) -- Skip ending apostrophe
end

local parse_value
local parse_key_value_pair

local function parse_inline_table(src, pos)
    pos = pos + 1
    local nested_dict = {}

    pos = skip_chars(src, pos, TOML_WS)
    if startswith(src, '}', pos) then
        return pos + 1, nested_dict
    end
    while true do
        local key, value
        pos, key, value = parse_key_value_pair(src, pos)
        local key_parent, key_stem = shallow_copy(key, 1, -1), key[#key]
        local nest = get_or_create_nest(nested_dict, key_parent, {access_lists=false})
        if nest[key_stem] then
            suffixed_err(src, pos, 'Duplicate inline table key ' .. torawstring(key_stem))
        end
        nest[key_stem] = value
        pos = skip_chars(src, pos, TOML_WS)
        local c = char(byte(src, pos))
        if c == '}' then
            return pos + 1, nested_dict
        end
        if c ~= ',' then
            suffixed_err(src, pos, 'Unclosed inline table')
        end
        pos = pos + 1
        pos = skip_chars(src, pos, TOML_WS)
    end
end

local function parse_array(src, pos)
    pos = pos + 1
    local array = {}

    pos = skip_comments_and_array_ws(src, pos)
    if startswith(src, ']', pos) then
        return pos + 1, array
    end
    while true do
        local val
        pos, val = parse_value(src, pos)
        insert(array, val)
        pos = skip_comments_and_array_ws(src, pos)

        local c = char(byte(src, pos))
        if c == ']' then
            return pos + 1, array
        end
        if c ~= ',' then
            suffixed_err(src, pos, 'Unclosed array')
        end
        pos = pos + 1

        pos = skip_comments_and_array_ws(src, pos)
        if startswith(src, ']', pos) then
            return pos + 1, array
        end
    end
end

local function parse_one_line_basic_str(src, pos)
    pos = pos + 1
    return parse_basic_str(src, pos, {multiline=false})
end

local function match_datetime(src, pos)
    -- RFC3339 datetime
    local first, last, year_str, month_str, day_str, hour_str, min_str, sec_str, secfrac_str, patt_end =
        find(src, '^(%d%d%d%d)%-(%d%d)%-(%d%d)[Tt](%d%d):(%d%d):(%d%d)%.?(%d*)()', pos)
    if not first then
        return nil
    end

    local offset
    if find(src, '^[Zz]', patt_end) then
        offset = 0
        last = last + 1
    else
        local sign_offset, hour_offset, min_offset = match(src, '^([+-])(%d%d):(%d%d)', patt_end)
        if not sign_offset then
            suffixed_err(src, patt_end, 'Invalid RFC 3339 timestamp offset')
        end
        offset = tonumber(hour_offset, 10) * 3600 + tonumber(min_offset, 10) * 60
        if sign_offset == '-' then
            offset = offset * -1
        end
        last = last + 6
    end

    return {
        first = first,
        last = last,
        fullyear = tonumber(year_str, 10),
        month = tonumber(month_str, 10),
        mday = tonumber(day_str, 10),
        hour = tonumber(hour_str, 10),
        minute = tonumber(min_str, 10),
        second = tonumber(sec_str, 10),
        secfrac = tonumber(secfrac_str .. rep('0', 6 - #secfrac_str), 10) or 0,
        offset = offset,
    }
end

local function match_localtime(src, pos)
    local first, last, hour_str, min_str, sec_str, secfrac_str =
        find(src, '^(%d%d):(%d%d):(%d%d)%.?(%d*)', pos)
    if not first then
        return nil
    end

    return {
        first = first,
        last = last,
        hour = tonumber(hour_str, 10),
        minute = tonumber(min_str, 10),
        second = tonumber(sec_str, 10),
        secfrac = tonumber(secfrac_str .. rep('0', 6 - #secfrac_str), 10) or 0,
    }
end

local function match_number(src, pos)
    local function matcher()
        local first, last, captured

        -- hex
        first, last, captured = find(src, '^0x([%x][%x_]*)', pos)
        if first then
            return first, last, gsub(captured, '_', ''), 16
        end

        -- bin
        first, last, captured = find(src, '^0b([01][01_]*)', pos)
        if captured then
            return first, last, gsub(captured, '_', ''), 2
        end

        -- oct
        first, last, captured = find(src, '^0o([0-7][0-7_]*)', pos)
        if captured then
            return first, last, gsub(captured, '_', ''), 8
        end

        -- dec
        -- FIXME: 指数表示 [eE] に対応する
        first, last, captured = find(src, '^([+-]?%d[%d_]*%.?%d?[%d_]*)', pos)
        if captured then
            return first, last, gsub(captured, '_', ''), 10
        end
    end

    local first, last, body, base = matcher()
    if not body then
        return nil
    end
    return {
        first = first,
        last = last,
        body = body,
        base = base,
    }
end

local function match_to_datetime(m)
    -- Returns a string because there is no datetime type.
    local full_date = format('%04d-%02d-%02d', m.fullyear, m.month, m.mday)
    local partial_time = format('%02d:%02d:%02d', m.hour, m.minute, m.second)
    if m.secfrac > 0 then
        local secfrac_str = tostring(m.secfrac)
        secfrac_str = rep('0', 6 - #secfrac_str) .. secfrac_str
        secfrac_str = gsub(secfrac_str, '0*$', '')
        partial_time = partial_time .. '.' .. secfrac_str
    end
    local offset_mins = m.offset / 60
    local time_offset = offset_mins == 0 and 'Z' or
        format('%+03d:%02d', offset_mins / 60, math.abs(offset_mins) % 60)
    return full_date .. 'T' .. partial_time .. time_offset
end

local function match_to_localtime(m)
    -- Return a string because there is no time type.
    local full_time = format('%02d:%02d:%02d', m.hour, m.minute, m.second)
    if m.secfrac > 0 then
        local secfrac_str = tostring(m.secfrac)
        secfrac_str = rep('0', 6 - #secfrac_str) .. secfrac_str
        secfrac_str = gsub(secfrac_str, '0*$', '')
        full_time = full_time .. '.' .. secfrac_str
    end
    return full_time
end

local function match_to_number(m)
    return tonumber(m.body, m.base)
end

function parse_value(src, pos)
    local c = char(byte(src, pos))

    -- IMPORTANT: order conditions based on speed of checking and likelihood

    -- Basic strings
    if c == '"' then
        if startswith(src, '"""', pos) then
            return parse_multiline_str(src, pos, {literal=false})
        end
        return parse_one_line_basic_str(src, pos)
    end

    -- Literal strings
    if c == "'" then
        if startswith(src, "'''", pos) then
            return parse_multiline_str(src, pos, {literal=true})
        end
        return parse_literal_str(src, pos)
    end

    -- Booleans
    if c == 't' then
        if startswith(src, 'true', pos) then
            return pos + 4, true
        end
    end
    if c == 'f' then
        if startswith(src, 'false', pos) then
            return pos + 5, false
        end
    end

    -- Arrays
    if c == '[' then
        return parse_array(src, pos)
    end

    -- Inline tables
    if c == '{' then
        return parse_inline_table(src, pos)
    end

    -- Dates and times
    local datetime_match = match_datetime(src, pos)
    if datetime_match then
        return datetime_match.last + 1, match_to_datetime(datetime_match)
    end
    local localtime_match = match_localtime(src, pos)
    if localtime_match then
        return localtime_match.last + 1, match_to_localtime(localtime_match)
    end

    -- Integers and "normal" floats.
    -- The regex will greedily match any type starting with a decimal
    -- char, so needs to be located after handling of dates and times.
    local number_match = match_number(src, pos)
    if number_match then
        return number_match.last + 1, match_to_number(number_match)
    end

    -- Special floats
    local first_three = sub(src, pos, pos + 2)
    if contains({'inf', 'nan'}, first_three) then
        return pos + 3, tonumber(first_three)
    end
    local first_four = sub(src, pos, pos + 3)
    if contains({'-inf', '+inf', '-nan', '+nan'}, first_four) then
        return pos + 4, tonumber(first_four)
    end

    suffixed_err(src, pos, 'Invalid value')
end

local function parse_key_part(src, pos)
    local c = char(byte(src, pos))
    if find(c, BARE_KEY_CHARS) then
        local start_pos = pos
        pos = skip_chars(src, pos, BARE_KEY_CHARS)
        return pos, sub(src, start_pos, pos - 1)
    end
    if c == "'" then
        return parse_literal_str(src, pos)
    end
    if c == '"' then
        return parse_one_line_basic_str(src, pos)
    end
    suffixed_err(src, pos, 'Invalid initial character for a key part')
end

local function parse_key(src, pos)
    local key_part
    pos, key_part = parse_key_part(src, pos)
    local key = {key_part,}
    pos = skip_chars(src, pos, TOML_WS)
    while true do
        local c = char(byte(src, pos))
        if c ~= '.' then
            return pos, key
        end
        pos = pos + 1
        pos = skip_chars(src, pos, TOML_WS)
        pos, key_part = parse_key_part(src, pos)
        insert(key, key_part)
        pos = skip_chars(src, pos, TOML_WS)
    end
    return pos, key
end

function parse_key_value_pair(src, pos)
    local key, value
    pos, key = parse_key(src, pos)
    local c = char(byte(src, pos))
    if c ~= '=' then
        suffixed_err(src, pos, "Expected '=' after a key in a key/value pair")
    end
    pos = pos + 1
    pos = skip_chars(src, pos, TOML_WS)
    pos, value = parse_value(src, pos)
    return pos, key, value
end

local function create_dict_rule(src, pos, out)
    pos = pos + 1 -- Skip '['
    pos = skip_chars(src, pos, TOML_WS)
    pos, key = parse_key(src, pos)

    get_or_create_nest(out, key)

    if not startswith(src, ']', pos) then
        suffixed_err(src, pos, "Expected ']' at the end of a table declaration")
    end
    return pos + 1, key
end

local function create_list_rule(src, pos, out)
    pos = pos + 2 -- Skip '[['
    pos = skip_chars(src, pos, TOML_WS)
    pos, key = parse_key(src, pos)

    append_nest_to_list(out, key)

    if not startswith(src, ']]', pos) then
        suffixed_err(src, pos, "Expected ']]' at the end of an array declaration")
    end
    return pos + 2, key
end

local function key_value_rule(src, pos, out, header)
    local key, value
    pos, key, value = parse_key_value_pair(src, pos)
    local key_parent, key_stem = shallow_copy(key, 1, -1), key[#key]
    local abs_key_parent = combine(header, key_parent)

    local nest = get_or_create_nest(out, abs_key_parent)
    if contains(nest, key_stem) then
        suffixed_err(src, pos, 'Cannot overwrite a value')
    end

    nest[key_stem] = value
    return pos
end

-- Parse TOML from a binary file object.
function _M.load(file)
    local s = file:read('a*')
    return _M.decode(s)
end

-- Parse TOML from a string.
function _M.decode(s)
    -- The spec allows converting "\r\n" to "\n", even in string
    -- literals. Let's do so to simplify parsing.
    local src = gsub(s, '\r\n', '\n')
    local pos = 1
    local out = {}
    local header = {}

    -- Parse one statement at a time
    -- (typically means one line in TOML source)
    while true do
        -- 1. Skip line leading whitespace
        local c
        pos, c = skip_chars(src, pos, TOML_WS)

        -- 2. Parse rules. Expect one of the following:
        --     - end of file
        --     - end of line
        --     - comment
        --     - key/value pair
        --     - append dict to list (and move to its namespace)
        --     - create dict (and move to its namespace)
        -- Skip trailing whitespace when applicable.
        if not c then
            break
        end
        if c ~= '\n' then
            if find(c, KEY_INITIAL_CHARS) then
                pos = key_value_rule(src, pos, out, header)
                pos = skip_chars(src, pos, TOML_WS)
            elseif c == '[' then
                local next_c = char(byte(src, pos + 1))
                if next_c == '[' then
                    pos, header = create_list_rule(src, pos, out)
                else
                    pos, header = create_dict_rule(src, pos, out)
                end
                pos = skip_chars(src, pos, TOML_WS)
            elseif c ~= '#' then
                suffixed_err(src, pos, 'Invalid statement')
            end
        end

        -- 3. Skip comment
        pos = skip_comment(src, pos)

        -- 4. Expect end of line or end of file
        c = char(byte(src, pos))
        if not c then
            break
        end
        if c ~= '\n' then
            suffixed_err(src, pos, 'Expected newline or end of document after a statement')
        end

        pos = pos + 1
    end

    return out
end

return _M

