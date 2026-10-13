//! The two derives uacrypt's Strumok uses, expanding to nothing.
use proc_macro::TokenStream;

#[proc_macro_derive(Zeroize)]
pub fn zeroize(_: TokenStream) -> TokenStream {
    TokenStream::new()
}

#[proc_macro_derive(ZeroizeOnDrop)]
pub fn zeroize_on_drop(_: TokenStream) -> TokenStream {
    TokenStream::new()
}
