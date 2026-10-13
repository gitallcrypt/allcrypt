//! zeroize's two derives, expanding to nothing.
use proc_macro::TokenStream;

#[proc_macro_derive(Zeroize, attributes(zeroize))]
pub fn zeroize(_: TokenStream) -> TokenStream {
    TokenStream::new()
}

#[proc_macro_derive(ZeroizeOnDrop, attributes(zeroize))]
pub fn zeroize_on_drop(_: TokenStream) -> TokenStream {
    TokenStream::new()
}
