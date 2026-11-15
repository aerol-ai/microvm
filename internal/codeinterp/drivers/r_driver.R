# AerolVM code interpreter driver for R.
#
# One process is one context: cells are evaluated in .GlobalEnv, which
# persists between runs. It speaks the frame protocol in
# internal/codeinterp/doc.go, "fd" mode only (toolboxd). Base R only;
# needs R 3.5 or newer (suspendInterrupts).
#
# Like a notebook's R kernel, each visible top-level value is printed as
# the console would print it and sent as a display result; print() and
# cat() output goes to stdout.
#
# Written for AerolVM (MIT). No code is taken from Daytona or E2B.

local({
  US <- "\x1f"
  # The host refuses frames over 32 MiB (codeinterp.MaxFramePayload).
  MAX_RESULT <- 16 * 1024 * 1024
  MAX_ERROR <- 1024 * 1024

  if (!identical(Sys.getenv("AEROL_INTERP_MODE"), "fd")) {
    cat("aerolvm interpreter driver: r runs only in fd mode\n", file = stderr())
    quit(save = "no", status = 1)
  }
  nonce <- Sys.getenv("AEROL_INTERP_NONCE")
  Sys.unsetenv(c("AEROL_INTERP_MODE", "AEROL_INTERP_NONCE"))
  # Frames are UTF-8, and in a C locale R prints "é" as "<U+00E9>". Images
  # often set no locale, so take a UTF-8 one for characters when there is
  # one; the rest of the locale stays the image's.
  if (!isTRUE(l10n_info()[["UTF-8"]])) {
    for (loc in c("C.UTF-8", "C.utf8", "en_US.UTF-8")) {
      if (nzchar(suppressWarnings(Sys.setlocale("LC_CTYPE", loc)))) break
    }
  }

  # Without the host's pipes, R's own script file may sit on fd 3. Linux
  # names a pipe "pipe:[inode]" there, a file by its path.
  opened <- if (startsWith(Sys.readlink("/proc/self/fd/3"), "/")) {
    simpleError("fd 3 is not a pipe")
  } else tryCatch(list(
    req = file("/dev/fd/3", open = "rb", raw = TRUE),
    ev = file("/dev/fd/4", open = "wb", raw = TRUE),
    # Private connections to fd 1 and 2 carry the markers, so sink() in a
    # cell cannot divert them.
    out = file("/dev/fd/1", open = "wb", raw = TRUE),
    err = file("/dev/fd/2", open = "wb", raw = TRUE)
  ), error = function(e) e)
  if (inherits(opened, "error")) {
    cat("aerolvm interpreter driver: protocol descriptors 3 and 4 are not open:",
        conditionMessage(opened), "\n", file = stderr())
    quit(save = "no", status = 1)
  }
  req <- opened$req
  ev <- opened$ev
  st <- new.env()
  st$seq <- 0
  st$count <- 0
  st$running <- FALSE
  st$done <- TRUE
  st$saved <- list()

  # ------------------------------------------------------------ frames

  emit <- function(kind, payload) {
    body <- if (is.raw(payload)) payload else charToRaw(enc2utf8(payload))
    writeBin(c(charToRaw(sprintf("%s %d\n", kind, length(body))), body), ev)
    flush(ev)
  }

  # sync orders the user's output before the next frame (doc.go).
  sync <- function() {
    flush(stdout())
    flush(stderr())
    st$seq <- st$seq + 1
    mark <- charToRaw(paste0("\x1e", nonce, ":", format(st$seq, scientific = FALSE), "\x1e"))
    for (con in list(opened$out, opened$err)) {
      try({
        writeBin(mark, con)
        flush(con)
      }, silent = TRUE)
    }
    emit("SYNC", format(st$seq, scientific = FALSE))
  }

  # read_frame returns list(kind, payload) or NULL at the end of the stream.
  read_frame <- function() {
    header <- raw(0)
    repeat {
      b <- readBin(req, "raw", 1L)
      if (length(b) == 0L) return(NULL)
      if (b == as.raw(10L)) break
      header <- c(header, b)
    }
    header <- rawToChar(header)
    sp <- regexpr(" ", header, fixed = TRUE)
    if (sp <= 1L) return(NULL)
    n <- suppressWarnings(as.numeric(substring(header, sp + 1L)))
    if (is.na(n) || n < 0) return(NULL)
    payload <- raw(0)
    while (length(payload) < n) {
      chunk <- readBin(req, "raw", n - length(payload))
      if (length(chunk) == 0L) return(NULL)
      payload <- c(payload, chunk)
    }
    list(kind = substr(header, 1L, sp - 1L), payload = payload)
  }

  # quietly runs driver bookkeeping with interrupts held back. An interrupt
  # that came meanwhile is dropped: it was meant for user code, which has
  # either not started or already ended.
  quietly <- function(expr) {
    tryCatch({
      suspendInterrupts(expr)
      # R raises a SIGINT that came during a blocking read only at its next
      # check, which would be inside the next cell. Sys.sleep(0) checks now.
      Sys.sleep(0)
    }, interrupt = function(i) invisible(NULL))
  }

  utf8 <- function(raw) {
    # An R string cannot hold NUL.
    s <- rawToChar(raw[raw != as.raw(0L)])
    Encoding(s) <- "UTF-8"
    s
  }

  # ---------------------------------------------------------- results

  json_string <- function(s) {
    s <- enc2utf8(s)
    for (p in list(c("\\", "\\\\"), c("\"", "\\\""), c("\n", "\\n"), c("\r", "\\r"), c("\t", "\\t"))) {
      s <- gsub(p[1], p[2], s, fixed = TRUE, useBytes = TRUE)
    }
    for (code in c(1:8, 11:12, 14:31)) {
      ch <- intToUtf8(code)
      if (grepl(ch, s, fixed = TRUE, useBytes = TRUE)) {
        s <- gsub(ch, sprintf("\\u%04x", code), s, fixed = TRUE, useBytes = TRUE)
      }
    }
    paste0("\"", s, "\"")
  }

  # format_value is the console's printout of a visible value.
  format_value <- function(value) {
    text <- paste(utils::capture.output(print(value)), collapse = "\n")
    if (nchar(text, type = "bytes") > MAX_RESULT / 4) {
      text <- paste0(substr(text, 1L, MAX_RESULT / 8), "\n... [truncated]")
    }
    text
  }

  # The call the driver evaluates each expression with; a condition raised
  # directly by the cell's top level carries it, and the console shows no
  # call there.
  eval_call <- quote(eval(expr, envir = .GlobalEnv))

  user_call <- function(cond) {
    call <- conditionCall(cond)
    if (is.null(call) || identical(call, eval_call)) NULL else call
  }

  # error_payload names every R error ERROR, as the notebook R kernel does;
  # the traceback is the console's "Error in call : message" line.
  error_payload <- function(cond, with_call = TRUE) {
    msg <- conditionMessage(cond)
    call <- if (with_call) user_call(cond) else NULL
    head <- if (is.null(call)) "Error: " else paste0("Error in ", paste(deparse(call, nlines = 1L), collapse = ""), " : ")
    tb <- paste0(head, msg)
    paste0("ERROR", US, substr(msg, 1L, MAX_ERROR), US, substr(tb, 1L, MAX_ERROR))
  }

  warn <- function(w) {
    call <- user_call(w)
    where <- if (is.null(call)) "" else paste0("In ", paste(deparse(call, nlines = 1L), collapse = ""), " : ")
    cat("Warning message:\n", where, conditionMessage(w), "\n", sep = "", file = stderr())
    invokeRestart("muffleWarning")
  }

  send_error <- function(payload) {
    quietly({
      sync()
      emit("ERROR", payload)
    })
  }

  # run_cell evaluates each top-level expression and returns the status.
  run_cell <- function(code) {
    exprs <- tryCatch(parse(text = code, keep.source = FALSE), error = function(e) e)
    if (inherits(exprs, "error")) {
      # The parser's message has the position; its call is the driver's.
      send_error(error_payload(exprs, with_call = FALSE))
      return("error")
    }
    for (expr in exprs) {
      # The value is printed inside the handlers: a print method's error is
      # the run's error and its warnings show at once.
      res <- withCallingHandlers(tryCatch({
        r <- withVisible(eval(expr, envir = .GlobalEnv))
        if (r$visible) list(text = format_value(r$value)) else list()
      }, error = function(e) e), warning = warn)
      if (inherits(res, "condition")) {
        send_error(error_payload(res))
        return("error")
      }
      if (!is.null(res$text)) {
        payload <- paste0("{\"data\":{\"text/plain\":", json_string(res$text), "},\"main\":false}")
        quietly({
          sync()
          emit("RESULT", payload)
        })
      }
    }
    "ok"
  }

  # ------------------------------------------------------------- runs

  apply_env <- function(pairs) {
    saved <- list()
    for (pair in pairs) {
      eq <- regexpr("=", pair, fixed = TRUE)
      if (eq <= 1L) next
      name <- substr(pair, 1L, eq - 1L)
      if (is.null(saved[[name]])) saved[[name]] <- Sys.getenv(name, unset = NA)
      # A name the platform refuses is skipped, not fatal.
      try(do.call(Sys.setenv, stats::setNames(list(substring(pair, eq + 1L)), name)), silent = TRUE)
    }
    saved
  }

  restore_env <- function(saved) {
    for (name in names(saved)) {
      old <- saved[[name]]
      try(if (is.na(old)) Sys.unsetenv(name) else do.call(Sys.setenv, stats::setNames(list(old), name)), silent = TRUE)
    }
  }

  finish <- function(status) {
    quietly({
      if (!st$done) {
        restore_env(st$saved)
        st$saved <- list()
        st$running <- FALSE
        sync()
        emit("DONE", status)
        st$done <- TRUE
      }
    })
  }

  execute <- function(code, pairs) {
    quietly({
      st$count <- st$count + 1
      st$saved <- apply_env(pairs)
      st$running <- TRUE
      st$done <- FALSE
      emit("COUNT", format(st$count, scientific = FALSE))
    })
    status <- tryCatch(run_cell(code), interrupt = function(i) "interrupted")
    finish(status)
  }

  # step handles one request. It returns FALSE when the context should end.
  env_pairs <- character(0)
  step <- function() {
    frame <- NULL
    quietly(frame <- read_frame())
    if (is.null(frame) || frame$kind == "QUIT") return(FALSE)
    if (frame$kind == "ENV") {
      env_pairs <<- c(env_pairs, utf8(frame$payload))
    } else if (frame$kind == "EXEC") {
      pairs <- env_pairs
      env_pairs <<- character(0)
      execute(utf8(frame$payload), pairs)
    }
    TRUE
  }

  emit("READY", "1")
  repeat {
    # An interrupt that slips between the guarded parts still ends the run
    # in progress with one DONE, and never the context.
    more <- tryCatch(step(), interrupt = function(i) {
      finish("interrupted")
      TRUE
    })
    if (!isTRUE(more)) break
  }
  quit(save = "no", status = 0)
})
