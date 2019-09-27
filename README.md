# masterpass
MasterPass php kütüphanesi


## not: 
Sadece Token Generatör'ünü kullanın masterpass ekibi javascript SDK sını incelemeden kullanmanıza izin vermeyecektir. Kendi kütüphanelerinde PHP token generatör olmadığından dolayı hazırlamış bulunmaktayım

```php
composer require akalod/masterpass

```php
use akalod\MasterPass;

echo MasterPass:generateToken($userId,$gsm);
