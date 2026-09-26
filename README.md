# lshlhom

**Protect Python files with layered encryption.**
**تشفير ملفات Python بطبقات حماية متتالية.**

عندك أداة بايثون وعايز توزعها للناس، بس ما بدك حد يشوف الكود أو يعدله؟ هذه المكتبة تسوي لك هذا الشي.

لما تحمي ملف، بتحصل على ملف `.py` ثاني يشتغل نفس الشي بالضبط، بس الكود الأصلي ما بيصير موجود فيه كنص، ولا حتى لو حد فحص الملف كله.

---

## Install / التثبيت

```
pip install lshlhom
```

ما تحتاج أي مكتبة خارجية. كل شي مدمج داخل المكتبة.

بدك طبقة الـ native؟ ثبّت Cython:


```
pip install lshlhom[native]
```

---

## Usage / الاستخدام

```python
import lshlhom

lshlhom.tshfer("my_tool.py")
```

بعد ما تشغل هذا الكود، بتحصل على ملف جديد اسمه:

```
my_tool_shlhom_azr.py
```

هذا الملف هو نفس الأداة بس محمية. وزّعها للناس، بتشتغل عندهم عادي.

---

## Command line / سطر الأوامر

```
lshlhom my_tool.py
lshlhom my_tool.py -o protected.py
lshlhom my_tool.py --no-native --size-kb 200
lshlhom my_tool.py --no-obfuscate
lshlhom --check protected.py
python -m lshlhom my_tool.py
```

| الخيار | شو يسوي |
| --- | --- |
| `-o, --output` | اسم ملف OUTPUT محدد |
| `-s, --size-kb` | الحد الأدنى لحجم الحمولة بالكيلوبايت، افتراضياً 800 |
| `--no-pad` | بدون تعبئة الحجم |
| `--no-native` | تخطي خطوة الـ binary، أسرع بكتير |
| `--no-obfuscate` | بدون تحويلات AST، بس التشفير |
| `--rename-defs` | تسمية الدوال أيضاً، ممكن يكسر استدعاء الخصائص |
| `--no-strict` | إذا فشل AST، كمّل بدونه بدل ما يوقف |
| `--seed` | بناء حتمي بمفتاح ثابت، يضعف الحماية |
| `--check` | تأكد إن الملف المحمي سليم |
| `-v, --verbose` | طباعة التفاصيل |

---

## Advanced Usage / الاستخدام المتقدم

```python
lshlhom.tshfer("my_tool.py", output="protected.py")
lshlhom.tshfer("my_tool.py", size_kb=1200)
lshlhom.tshfer("my_tool.py", native=False)
lshlhom.tshfer("my_tool.py", obfuscate=False, pad=False)
lshlhom.tshfer("my_tool.py", strict=False)
lshlhom.protect("my_tool.py")
```

`tshfer` و `protect` اسمان لنفس الدالة.

### Persistent error type / نوع الخطأ

كل أخطاء المكتلة ترجع `lshlhom.ShlhomError`:

```python
from lshlhom import ShlhomError

try:
    lshlhom.tshfer("my_tool.py")
except ShlhomError as exc:
    print(exc)
```

---

## What actually happens / شو يصير بالضبط

المكتبة تطبّق الطبقات بالترتيب التالي على الكود اللي إنت كاتب:

### 1. تحويلات AST

- **إعادة تسمية المتغيرات**: المتغيرات المحلية تتحول لأسماء مبنية على hash
- **تشويش تدفق التحكم**: الدوال البسيطة تتحول إلى `while` مع state machine
- **تشفير النصوص**: كل `str` و `bytes` يتشفر بـ SM4-CBC
- **تنظيف**: الـ docstrings والشيفرة الميتة بينحذفوا

### 2. Marshal Serialization

تحويل الكود إلى bytecode بايثون عبر `marshal`، ثم ضغطه بـ `zlib`.

### 3. XOR Stream مزدوج

طبقتَي XOR بمفاتيح عشوائية، طبقة فوق طبقة.

### 4. تشفير SM4-CBC

خوارزمية SM4، التشفير الوطني الصيني الرسمي، بديل AES في الصين.

### 5. ضغط Huffman

ضغط البيانات بـ Huffman tree مخصصة، والشجرة تنحفظ مع البيانات.

### 6. ترميز Base91

ترميز Base91 بدل Base64، أكثر كثافة وأقل حجماً.

### 7. Native binary / اختياري

إذا كان `cython` و `gcc` أو `clang` مثبتين، المكتبة تبني binary حقيقي من الكود المشفّر وتحطه جوّا الملف الناتج. إذا ما كانوا موجودين، بتستخدم `marshal` بدالهم. استعمل `--no-native` إذا بدك سرعه.

### 8. حاوية ZIP + فحص سلامة

الحمولة تنحط جوّا حاوية، جوّاها بصمة `SHA-256`. لما المستخدم يشغّل الملف، البصمة بتتحقق قبل ما الكود ينفّذ. إذا حد عدّل الملف، التشغيل بيوقف برسالة واضحة.

---

## How the output file works / كيف يشتغل الملف الناتج

الملف الناتج (`*_shlhom_azr.py`) بيشتغل على أي جهاز فيه Python 3.9 أو أحدث، وما بيحتاج مكتبات.

1. الملف بيتحقق من نفسه
2. بيفك الحاوية ويفحص البصمة
3. بيفك الطبقات كلها
4. بيشغّل الكود الأصلي بالذاكرة

`__file__` و `sys.argv[0]` و `__name__` بيرجعوا لملف `.py` نفسه، وكود الخروج بينزل زي ما هو.

كل هذا بصير بالذاكرة فقط. الكود الأصلي ما بيحفظ في أي مكان، ومجلدات العمل بتنحذف بعد التشغيل.

---

## Requirements / المتطلبات

- Python 3.9 أو أحدث
- بدون مكتبات خارجية
- للطبقة الـ native: `cython` و `gcc` أو `clang`
- المدعوم رسمياً: Termux, Linux, Android
- Windows و macOS اشتغلوا بالوضع بدون native

---

## Use Cases / متى تنفعك

- عندك أداة بايثون وبدك توزعها للناس
- ما بدك حد يشوف المنطق الداخلي
- ما بدك حد يعدل الكود
- ما بدك حد يسرق الفكرة
- بدك تحمي كودك من النسخ

## When not to use / متى ما تنفعك

- إذا الكود بيحتاج أداء عالي جداً
- إذا الملف فيه بيانات ضخمة مدمجة
- إذا عم توزع الكود مفتوح المصدر، هذه المكتبة ضد الفكرة

---

## Notes on protection / ملاحظات مهمة

- هذه الحماية بتعيق القراءة السريعة والتعديل، ما هي حماية عسكرية. أي حد يقدر يفك الكود إذا بذل مجهود حقيقي.
- **مهم**: الملف المحمي لازم يتشغّل بنفس نسخة Python اللي انبنى عليها، لأن `marshal` مرتبط بإصدار بايثون. ينفع تبنيه وتشغّله على نفس الجهاز أو نفس العائلة.
- استعمل `seed` فقط للاختبارات. مع `seed` أي حد يقدر يبني نفس الملف.
- `rename_defs` تسمّي الدوال، وهذا بيكسر `obj.method()` و `getattr(obj, "name")`. خلّيها مقفلة إلا إذا عرفت شو بصير.
- افحص الملف الناتج قبل ما توزعه. لو في خطأ بيشتغل وقت التشغيل، بيبان عند المستخدم مو عندك.

---

## Development / التطوير

```
python -m unittest discover -s tests -v
```

الاختبارات بدون أي مكتبات خارجية.

---

## Credits / الحقوق

- **المكتبة الأصلية والحقوق الأصلية**: shlhom
  - Email: adojod1231@gmail.com
  - Telegram: @yy22ff
- **مطوّر مشارك لنسخة 1.1.0**: AZR
  - Telegram: @AZR_hk

## License

MIT
