//! PC/SC, the operating system's smart card service, loaded when it is
//! first used rather than linked.
//!
//! Every desktop system has it: `winscard.dll` on Windows, the PCSC
//! framework on macOS, and pcsc-lite's `libpcsclite.so.1` on Linux and
//! the BSDs, which talks to the `pcscd` daemon. Loading the library at run
//! time rather than linking it means the example builds everywhere,
//! including machines with no smart card stack at all, and says so only
//! when a card is actually asked for - the same reason the `libssl` shim
//! resolves libcrypto with `dlsym`.
//!
//! **This file is the example's only `unsafe`.** Calling a C function is
//! unsafe by definition, and the four functions here pass buffers whose
//! lengths they state; every pointer handed over is to memory this file
//! owns for the duration of the call. Nothing else in the example needs
//! it, and the library has none.
//!
//! The one portability trap is the integer types. Windows and macOS
//! declare `DWORD` and `LONG` as 32-bit; pcsc-lite declares them as C's
//! `unsigned long` and `long`, which are 64-bit on 64-bit Linux. The
//! handle types differ the same way. Getting this wrong corrupts the stack
//! on one platform and works on the others.

use std::ffi::{c_char, c_void, CString};
use std::rc::Rc;

#[cfg(windows)]
mod types {
    pub type Dword = u32;
    pub type Long = i32;
    pub type Context = usize;
    pub type Handle = usize;
    pub const LIBRARY: &str = "winscard.dll";
    pub const LIST_READERS: &str = "SCardListReadersA";
    pub const CONNECT: &str = "SCardConnectA";
}

#[cfg(target_os = "macos")]
mod types {
    pub type Dword = u32;
    pub type Long = i32;
    pub type Context = i32;
    pub type Handle = i32;
    pub const LIBRARY: &str = "/System/Library/Frameworks/PCSC.framework/PCSC";
    pub const LIST_READERS: &str = "SCardListReaders";
    pub const CONNECT: &str = "SCardConnect";
}

#[cfg(all(unix, not(target_os = "macos")))]
mod types {
    pub type Dword = std::ffi::c_ulong;
    pub type Long = std::ffi::c_long;
    pub type Context = std::ffi::c_long;
    pub type Handle = std::ffi::c_long;
    pub const LIBRARY: &str = "libpcsclite.so.1";
    pub const LIST_READERS: &str = "SCardListReaders";
    pub const CONNECT: &str = "SCardConnect";
}

use types::{Context as RawContext, Dword, Handle, Long};

const SCARD_SCOPE_USER: Dword = 0;
const SCARD_SHARE_SHARED: Dword = 2;
const SCARD_PROTOCOL_T0: Dword = 1;
const SCARD_PROTOCOL_T1: Dword = 2;
const SCARD_LEAVE_CARD: Dword = 0;
const NO_READERS: u32 = 0x8010_002E;

/// `SCARD_IO_REQUEST`: the protocol, and the size of this header.
#[repr(C)]
struct IoRequest {
    protocol: Dword,
    length: Dword,
}

type EstablishContext =
    unsafe extern "system" fn(Dword, *const c_void, *const c_void, *mut RawContext) -> Long;
type ReleaseContext = unsafe extern "system" fn(RawContext) -> Long;
type ListReaders =
    unsafe extern "system" fn(RawContext, *const c_char, *mut c_char, *mut Dword) -> Long;
type Connect = unsafe extern "system" fn(RawContext, *const c_char, Dword, Dword, *mut Handle,
                                         *mut Dword) -> Long;
type Transmit = unsafe extern "system" fn(Handle, *const IoRequest, *const u8, Dword,
                                          *mut IoRequest, *mut u8, *mut Dword) -> Long;
type Disconnect = unsafe extern "system" fn(Handle, Dword) -> Long;

#[cfg(unix)]
mod loader {
    use std::ffi::{c_char, c_int, c_void};
    extern "C" {
        fn dlopen(name: *const c_char, flags: c_int) -> *mut c_void;
        fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
    }
    const RTLD_NOW: c_int = 2;
    pub fn open(name: &std::ffi::CStr) -> *mut c_void {
        // SAFETY: `name` is a NUL-terminated string that outlives the call.
        unsafe { dlopen(name.as_ptr(), RTLD_NOW) }
    }
    pub fn symbol(library: *mut c_void, name: &std::ffi::CStr) -> *mut c_void {
        // SAFETY: `library` came from `dlopen` and was checked non-null.
        unsafe { dlsym(library, name.as_ptr()) }
    }
}

#[cfg(windows)]
mod loader {
    use std::ffi::{c_char, c_void};
    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryA(name: *const c_char) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
    }
    pub fn open(name: &std::ffi::CStr) -> *mut c_void {
        // SAFETY: `name` is a NUL-terminated string that outlives the call.
        unsafe { LoadLibraryA(name.as_ptr()) }
    }
    pub fn symbol(library: *mut c_void, name: &std::ffi::CStr) -> *mut c_void {
        // SAFETY: `library` came from `LoadLibraryA` and was checked non-null.
        unsafe { GetProcAddress(library, name.as_ptr()) }
    }
}

/// The PC/SC functions, resolved from the system library.
struct Library {
    establish: EstablishContext,
    release: ReleaseContext,
    list: ListReaders,
    connect: Connect,
    transmit: Transmit,
    disconnect: Disconnect,
}

impl Library {
    fn load() -> Result<Library, String> {
        let name = CString::new(types::LIBRARY).expect("no NUL in a library name");
        let library = loader::open(&name);
        if library.is_null() {
            return Err(format!("The smart card service is not installed: {} could not be \
                                loaded. On Linux that is pcsc-lite (the pcscd package).",
                               types::LIBRARY));
        }
        let find = |symbol: &str| -> Result<*mut c_void, String> {
            let c_name = CString::new(symbol).expect("no NUL in a symbol name");
            let address = loader::symbol(library, &c_name);
            if address.is_null() {
                Err(format!("{} has no {symbol}.", types::LIBRARY))
            } else {
                Ok(address)
            }
        };
        // SAFETY: each address is the named PC/SC function, whose C
        // signature the type it is converted to transcribes, with the
        // platform's integer widths from `types`.
        unsafe {
            Ok(Library {
                establish: std::mem::transmute::<*mut c_void, EstablishContext>(
                    find("SCardEstablishContext")?),
                release: std::mem::transmute::<*mut c_void, ReleaseContext>(
                    find("SCardReleaseContext")?),
                list: std::mem::transmute::<*mut c_void, ListReaders>(
                    find(types::LIST_READERS)?),
                connect: std::mem::transmute::<*mut c_void, Connect>(find(types::CONNECT)?),
                transmit: std::mem::transmute::<*mut c_void, Transmit>(
                    find("SCardTransmit")?),
                disconnect: std::mem::transmute::<*mut c_void, Disconnect>(
                    find("SCardDisconnect")?),
            })
        }
    }
}

/// PC/SC's error codes, with what each means to someone holding a card.
fn describe(code: Long) -> String {
    let unsigned = code as u32;
    let meaning = match unsigned {
        0x8010_0002 => "the operation was cancelled",
        0x8010_0003 => "the reader name is not one PC/SC knows",
        0x8010_0008 => "the response did not fit the buffer",
        0x8010_000B => "another program holds the card exclusively",
        0x8010_000C => "there is no card in the reader",
        0x8010_000F => "the card does not speak the requested protocol",
        0x8010_0016 => "the reader is not ready",
        0x8010_0017 => "the reader is unavailable",
        0x8010_001D => "the smart card service is not running (pcscd on Linux)",
        0x8010_002E => "no smart card reader is connected",
        0x8010_0069 => "the card was removed",
        0x8010_0068 => "the card was reset by another program",
        0x8010_0066 => "the card is not responding",
        _ => "",
    };
    if meaning.is_empty() {
        format!("PC/SC error 0x{unsigned:08X}")
    } else {
        format!("PC/SC error 0x{unsigned:08X}: {meaning}")
    }
}

fn check(code: Long, what: &str) -> Result<(), String> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!("{what}: {}.", describe(code)))
    }
}

/// The service's context, released when the last user is dropped.
struct Context {
    library: Library,
    handle: RawContext,
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: the handle came from `SCardEstablishContext`.
        unsafe {
            (self.library.release)(self.handle);
        }
    }
}

/// A connection to the smart card service.
pub struct Pcsc {
    context: Rc<Context>,
}

impl Pcsc {
    pub fn establish() -> Result<Pcsc, String> {
        let library = Library::load()?;
        let mut handle: RawContext = 0;
        // SAFETY: `handle` is a valid place for the function to write
        // the context, and the two reserved pointers must be null.
        let code = unsafe {
            (library.establish)(SCARD_SCOPE_USER, std::ptr::null(), std::ptr::null(), &mut handle)
        };
        check(code, "Connecting to the smart card service")?;
        Ok(Pcsc { context: Rc::new(Context { library, handle }) })
    }

    /// The names of the readers PC/SC can see.
    pub fn readers(&self) -> Result<Vec<String>, String> {
        let context = &self.context;
        let mut length: Dword = 0;
        // SAFETY: a null buffer asks for the length, written to `length`.
        let code = unsafe {
            (context.library.list)(context.handle, std::ptr::null(), std::ptr::null_mut(),
                                   &mut length)
        };
        if code as u32 == NO_READERS {
            return Ok(Vec::new());
        }
        check(code, "Listing the readers")?;
        let mut buffer = vec![0u8; length as usize];
        // SAFETY: `buffer` has the `length` bytes the call just asked for.
        let code = unsafe {
            (context.library.list)(context.handle, std::ptr::null(),
                                   buffer.as_mut_ptr() as *mut c_char, &mut length)
        };
        if code as u32 == NO_READERS {
            return Ok(Vec::new());
        }
        check(code, "Listing the readers")?;
        // A "multi-string": names separated by NUL, ended by an empty one.
        Ok(buffer[..(length as usize).min(buffer.len())]
            .split(|&b| b == 0)
            .filter(|name| !name.is_empty())
            .map(|name| String::from_utf8_lossy(name).into_owned())
            .collect())
    }

    /// Connect to the card in `reader`, T=1 or T=0, shared with other
    /// programs.
    pub fn connect(&self, reader: &str) -> Result<Connection, String> {
        let name = CString::new(reader).map_err(|_| "A reader name has a NUL.".to_string())?;
        let mut handle: Handle = 0;
        let mut protocol: Dword = 0;
        // SAFETY: `name` is NUL-terminated; `handle` and `protocol` are
        // valid places for the results.
        let code = unsafe {
            (self.context.library.connect)(self.context.handle, name.as_ptr(),
                                           SCARD_SHARE_SHARED,
                                           SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &mut handle,
                                           &mut protocol)
        };
        check(code, &format!("Connecting to the card in {reader}"))?;
        Ok(Connection { context: Rc::clone(&self.context), handle, protocol })
    }
}

/// A connected card. Disconnecting leaves the card as it is, so a PIN
/// verified here stays verified for the next program, as other PC/SC
/// clients behave.
pub struct Connection {
    context: Rc<Context>,
    handle: Handle,
    protocol: Dword,
}

impl super::card::Transport for Connection {
    /// One APDU out, one response in: data followed by the two status
    /// bytes.
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, String> {
        let request = IoRequest {
            protocol: self.protocol,
            length: std::mem::size_of::<IoRequest>() as Dword,
        };
        // Room for an extended response: 65,536 bytes and the status.
        let mut response = vec![0u8; 65_538];
        let mut length = response.len() as Dword;
        // SAFETY: `apdu` is `apdu.len()` readable bytes, `response` is
        // `length` writable bytes, `request` describes the connection's
        // protocol, and a null receive header is allowed.
        let code = unsafe {
            (self.context.library.transmit)(self.handle, &request, apdu.as_ptr(),
                                            apdu.len() as Dword, std::ptr::null_mut(),
                                            response.as_mut_ptr(), &mut length)
        };
        check(code, "Sending a command to the card")?;
        response.truncate(length as usize);
        Ok(response)
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // SAFETY: the handle came from `SCardConnect` on this context,
        // which the `Rc` keeps alive.
        unsafe {
            (self.context.library.disconnect)(self.handle, SCARD_LEAVE_CARD);
        }
    }
}
