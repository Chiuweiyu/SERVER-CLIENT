# SERVER-CLIENT
* 網路技術與應用期末專案

一套具安全傳輸的簡單網際網路第三方支付使用者對使用者小額付款（Micropayment）系統。此系統包含三大功能：

一、第三方支付 Server 端對 Client 端（使用者）的統一管理，包含帳號管理、好友名單管理、認證以及 Client 帳戶管理等。

二、Client 間即時通訊。

三、Client 與 Server 以及 Client 間的通訊，都可以各自加密，加密的鑰匙由當下通訊的雙方議定。

本專案是設計與實作一套簡單的好友間轉帳功能。實作一套「安全的第三方支付使用者對使用者小額付款系統」

包含 Client 與 multithreaded Server 端的軟體，以及安全傳輸的軟體撰寫。

Client 端的兩個主要功能：

* 安全的與第三方支付 Server 的通訊

* 一對一安全的 Client 間對談

Multi-threaded Server 端的主要功能：

* 接受 Client 的安全連結，並根據要求（request）回覆訊息（reply）

安全通訊的主要功能：
* 每一個 Client 與 Server 間，以及 Client 間的通訊，都必須加密，加密的鑰匙
（encryption key，又稱 secret key）由當下通訊的雙方議定。
