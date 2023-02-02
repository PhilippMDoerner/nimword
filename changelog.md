# Changelog

-   [!]—backward incompatible change
-   [+]—new feature
-   [f]—bugfix
-   [r]—refactoring
-   [t]—test suite improvement
-   [d]—docs improvement


## 0.2.0 (Febuary 02, 2022)
- [r] Add `raise` pragma to public-api to enforce users to deal with potential exceptions
- [d] Add info to Readme.md to install libsodium/openssl for usage 
- [d] Add changelog.md
- [r] Moved fetching `EVP_MD_get_size`/ `EVP_MD_size` depending on Openssl version out of a proc and into global space so that it fails on startup rather than at actual runtime.

## 0.1.0 (Febuary 02, 2023)
-   🎉 initial release.