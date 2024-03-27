#pragma once
#include <string>

class jsonwriter
{
  enum jsonwriter_mode {
    none             = 0x001000001,
    in_object        = 0x010000002,
    in_array         = 0x101000003,
    in_field         = 0x101000004,
    error            = 0x000000099,
    overflowed       = 0x00000009,
    finished         = 0x000000100,
    pre_object_array = 0x001000000,
    pre_field        = 0x010000000,
    pre_literal      = 0x100000000

  };
  struct mode_element {
    jsonwriter_mode mode;
    bool first;
  };
  struct mode_element mode_stack[20];
  int mode_stack_depth = 0;
  char *_message       = nullptr;
  char *_current       = nullptr;
  char *_end           = nullptr;
  bool _valid          = false;

public:
  jsonwriter(char *message, int length) : _message(message), _current(message), _end(message + length - 1)
  {
    mode_stack[0].first = true;
    mode_stack[0].mode  = none;
  }
  inline jsonwriter_mode
  current_mode()
  {
    return mode_stack[mode_stack_depth].mode;
  }

  inline bool
  first()
  {
    return mode_stack[mode_stack_depth].first;
  }
  inline void
  reset_first()
  {
    mode_stack[mode_stack_depth].first = false;
  }

  inline void
  set_mode(jsonwriter_mode mode)
  {
    mode_stack_depth++;
    mode_stack[mode_stack_depth].first = true;
    mode_stack[mode_stack_depth].mode  = mode;
  }
  inline void
  pop_mode()
  {
    mode_stack_depth--;
  }
  bool
  addpair(const char *field, const char *data, bool skip_empty = true, bool literaldata = false)
  {
    if (data == nullptr)
      data = "";
    if (data[0] == 0 && skip_empty)
      return true;
    if ((current_mode() & jsonwriter_mode::pre_field) != pre_field) {
      set_mode(error);
      return false;
    }
    checkfirst();
    addjsonstring(field);
    addstring(":");
    if (literaldata)
      addstring(data);
    else
      addjsonstring(data);
    return _current != _end;
  }
  inline void
  addstring(const char *data)
  {
    while (*data && _current != _end) {
      *_current++ = *data++;
    }
  }
  inline void
  addjsonstring(const char *data)
  {
    addstring("\"");
    while (*data && _current != _end) {
      unsigned char c = (unsigned char)*data++, control = 0;
      switch (c) {
      case '\n':
        control = 'n';
        break;
      case '\r':
        control = 'r';
        break;
      case '"':
        control = '"';
        break;
      case '\'':
        control = '\'';
        break;
      case '\\':
        control = '\\';
        break;
      case '\t':
        control = 't';
        break;
      case '\b':
        control = 'b';
        break;
      case '\f':
        control = 'f';
        break;
      default:
        if (c < 32) {
          char hexstring[7];
          sprintf(hexstring, "\\u%04x", (int)c);
          addstring(hexstring);
          continue;
        }
        *_current++ = (char)c;
        continue;
      }
      if (_current == (_end - 2)) {
        _end = _current;
        continue;
      }
      *_current++ = '\\';
      *_current++ = control;
    }
    addstring("\"");
  }
  bool
  addfield(const char *field)
  {
    if ((current_mode() & jsonwriter_mode::pre_field) != pre_field) {
      set_mode(jsonwriter_mode::error);
      return false;
    }
    checkfirst();
    set_mode(jsonwriter_mode::in_field);
    addjsonstring(field);
    addstring(":");
    return true;
  }
  bool
  addliteral(const char *data, bool literal_data = false)
  {
    bool in_field = current_mode() == jsonwriter_mode::in_field;
    if ((current_mode() & jsonwriter_mode::pre_literal) != pre_literal) {
      set_mode(jsonwriter_mode::error);
      return false;
    }
    if (!in_field)
      checkfirst();
    addjsonstring(data);
    if (in_field) {
      pop_mode();
    }
    if (current_mode() == jsonwriter_mode::none) {
      set_mode(overflow() ? jsonwriter_mode::error : jsonwriter_mode::finished);
    }
    return overflow();
  }
  bool
  addpair(const char *field, bool data)
  {
    return addpair(field, data ? "true" : "false", false, true);
  }

  bool
  addpair(const char *field, int data, bool skip_empty = true, int empty_value = 0)
  {
    if (skip_empty && data == empty_value)
      return true;
    auto sdata = std::to_string(data);
    return addpair(field, sdata.c_str(), true, true);
  }
  bool
  addpair(const char *field, long data, bool skip_empty = true, int empty_value = 0)
  {
    if (skip_empty && data == empty_value)
      return true;
    auto sdata = std::to_string(data);
    return addpair(field, sdata.c_str(), true, true);
  }
  bool
  addpair(const char *field, struct sockaddr *addr, bool skip_empty = true)
  {
    if ((current_mode() & jsonwriter_mode::in_object) != in_object) {
    }
    if (skip_empty && addr == nullptr)
      return true;
    return false;

    // addpair(field, TSIPNPToP(addr, ip, 200), true, true);
  }
  void
  checkfirst()
  {
    auto mode = current_mode();
    if (!first() && (mode == jsonwriter_mode::in_array || mode == jsonwriter_mode::in_object)) {
      addstring(",");
    } else {
      reset_first();
    }
  }
  bool
  open_array()
  {
    if ((current_mode() & jsonwriter_mode::pre_object_array) != pre_object_array) {
      set_mode(jsonwriter_mode::error);
      // todo, error
      return false;
    }
    checkfirst();

    addstring("[");
    set_mode(jsonwriter_mode::in_array);
  }
  bool
  close_array()
  {
    if (current_mode() != jsonwriter_mode::in_array) {
      set_mode(jsonwriter_mode::error);
      // todo, error
      return false;
    }
    addstring("]");
    pop_mode();
    if (current_mode() == jsonwriter_mode::none) {
      *_current = 0;
      set_mode(overflow() ? jsonwriter_mode::error : jsonwriter_mode::finished);
    }
    if (current_mode() == jsonwriter_mode::in_field) {
      pop_mode();
    }
    return current_mode() != jsonwriter_mode::error;
  }
  bool
  open_object()
  {
    if ((current_mode() & jsonwriter_mode::pre_object_array) != pre_object_array) {
      set_mode(jsonwriter_mode::error);
      // todo, error
      return false;
    }
    checkfirst();
    addstring("{");
    set_mode(jsonwriter_mode::in_object);
    return true;
  }
  bool
  close_object()
  {
    if (current_mode() != jsonwriter_mode::in_object) {
      set_mode(jsonwriter_mode::error);
      // todo, error
      return false;
    }
    addstring("}");
    pop_mode();
    if (current_mode() == jsonwriter_mode::none) {
      *_current = 0;
      set_mode(overflow() ? jsonwriter_mode::error : jsonwriter_mode::finished);
    }
    if (current_mode() == jsonwriter_mode::in_field) {
      pop_mode();
    }
    return current_mode() != jsonwriter_mode::error;
  }
  inline bool
  overflow()
  {
    return _current == _end;
  }
  bool
  valid()
  {
    return current_mode() == jsonwriter_mode::finished;
  }
};
