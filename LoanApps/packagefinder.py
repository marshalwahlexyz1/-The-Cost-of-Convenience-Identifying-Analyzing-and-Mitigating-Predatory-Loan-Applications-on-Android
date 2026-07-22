import pandas as pd

# Define groups by country and classification.
groups = {
    ("Indonesia", "approved"): {
        "com.danamas.mergingapp",
        "com.amarthaplus.amarthabeyond",
        "id.co.tokomodal.mobile",
        "com.ktakilat.loan",
        "com.kreditpintar",
        "com.akseleran.crowdfund",
        "com.ammana.app",
        "com.pinjamango",
        "com.adakami.dana.kredit.pinjaman",
        "com.estakapital.investor"
    },
    ("Philippines", "approved"): {
        "com.Loanmoto.www",
        "com.pera4u.peso",
        "com.Surity.loan.lendingapp.cash.peso.borrowmoney.ph",
        "in.fire.dazy.ame.lucky",
        "com.loan.quick"
    },
    ("Pakistan", "approved"): {
        "com.personale.credit.carry.cash.loan.paisaya",
        "com.aitemaad.money.credit.cash.easy.loan",
        "com.waleefinancialservices.hakeem",
        "com.fauricash.credit.loan",
        "com.creditcat.tech.app",
        "com.techlogix.mobilinkcustomer",
        "com.dhan.quick.udhaar.tap.game.jaldi.paisa.borrow",
        "com.loan.easy.cash.pakcredit.paisa.dhan.tez.dhan",
        "com.finleap.daira",
        "com.personal.loan.loanlado.credit.easy.jazz.online.cash",
        "com.abhifinance",
        "com.raqqam.monamitech",
        "com.tech.qistbazar",
        "com.creditbookpk.creditbook",
        "com.neempaymenow.app"
    },
    ("Pakistan", "delisted"): {
        "com.capitalpoint.easycashloans",
        "com.optipay.littlecash",
        "com.superb.loans.borrownow",
        "com.fairlend.fairloans",
        "com.plati.feb.loans",
        "com.fori.ready.naqd.paisa.jazz.foriqarz",
        "com.quickcash.pak.appv001.io",
        "com.campsite.debit.pk.gold.simple",
        "com.easyloans.solutions",
        "com.metaloanpro.app",
        "com.didiloans.android",
        "com.rapidpayapps.finepayloans",
        "app.lendhome.com",
        "com.pk.finmore",
        "com.pakist.loan.aicash",
        "com.pak.qarza.cash.app",
        "com.user.vay.pakistan",
        "com.instantloan.easy.fast.credit.mobile.cash.loan.forimoney",
        "rpo1.muvfwokh.merarupiya",
        "com.pak.loan.creditharsha.app",
        "com.loanclub.lcapp",
        "com.usxkwl.imzulitu",
        "com.dspj.ajhdi.tazza",
        "com.pak.api.aasancash.app",
        "com.credit.pk.cash",
        "com.kaka.kuka",
        "com.natd.snoa",
        "com.pk.cashwin",
        "com.pk.cashpro",
        "pk.credit.loan.rosecash",
        "com.hamdardloan.android",
        "get.it.now.fast.app",
        "com.pkst.gdtdkaa",
        "com.moneybox.pkbox",
        "com.rkmyb.cotmyc",
        "com.vt.yang.yocash",
        "com.oxygen.salkm",
        "com.whaleloan.mobile.pkg",
        "com.oshuf.zen.atgwu",
        "com.jsnwvcm.rpesltp",
        "co.tw.qz_app",
        "ijuyiewj.k94899wtewrwe",
        "ifdjfdgl.dkf675tyuhgtj",
        "com.tqbdtmava.ftwnyrwdvx.ouwdb",
        "credit.prestamos.personale.cash.loan.barwaqt.credstar",
        "com.lend.play.paisa.credit.kredit.game.dhan.easy.loan.miniloan.jaldi",
        "com.easyloans.instantloans.foriloan",
        "iashbfias.fbisdiofbwieuisadfo",
        "com.arham.mycash",
        "apple.poasufgdschfsdkfdskf",
        "com.conte.ntspoc.kpaytm.tiktok.jazzcash.tasker.yota",
        "on8ajuqw.ekagsdifqabfewf",
        "com.jaidicredit.app",
        "com.swifts.mobile.loans",
        "lkdsfndskldnf.abc",
        "com.metaloanmy.app",
        "com.simpleloan.instant.suparkash",
        "host.easypocket.moblie.release",
        "com.apdlym.wsnnwrjlu",
        "com.holiday.loan.pk.com",
        "com.credit.now",
        "com.game.rupee.dhan.borrow.credit.kredit.daily.jaldi.easy.play.udhaar.cash",
        "com.loan.okwallet.paki",
        "com.pk.colecas",
        "com.fintech.quick.cash.focusloan",
        "com.darm.personaloans",
        "com.geeklabdevelopers.wcashloan",
        "pakkicash.cash.pk",
        "com.loanmarket",
        "com.candycash.cash",
        "com.mdul.pakk.gyert",
        "com.guide.loper",
        "com.cash.quicklylend",
        "com.cbnldllk.nvkkjn.zxycs",
        "com.bk.cash.loan",
        "com.galaxy.wallet.kill.bare.in",
        "com.cash.apoyo.credit.lana.lending.branch.tala.credito.yumi.ifectivo",
        "com.app.easycredit",
        "com.quicklending.mart",
        "com.singleclick.loanpe.trading.colourloan.b2l",
        "com.hipkloan.easypaisa.jazzcash.credit",
        "com.cash.sh.run",
        "com.pakistan.moonlan",
        "com.pk.expressloan.cash",
        "com.pkr.loan",
        "com.soulfaquick.soulfa",
        "com.uylusw.udimxl.ammxrs",
        "com.mango.onlycreditfast",
        "com.fairercredit.readyloans",
        "com.flexyguide.quickloan",
        "com.financeapp.credicash.easycashloan",
        "com.tqbdtmava.ftwnyrwdvx.ouwdbf",
        "com.timproject.pakistantw",
        "com.supeman.loan.ffvop.idfgpp",
        "com.hellacash.dassw.rqhww",
        "com.wicash.pk",
        "com.tonafishfi.funatiamcrea",
        "com.ftfarm.fibo",
        "com.helacreditloans",
        "com.happycredit.inc.fast.max",
        "com.getinstantloan.creditloan.cashloan",
        "com.paisaloanguide.loanguidepaisatips",
        "cn.lk.creat",
        "com.twentythreeloans",
        "com.bjst1.zwgsht",
        "get.minutes.credit.cash",
        "gshtmkf.kakcrbh.dyycpirm.misjrf",
        "com.jalurlaba.app",
        "com.loanapp.onlineloan.applyonline.calc.Bankbalancecheck",
        "com.loan.aadhar.pan.insurance.calculator.getloanonpancard",
        "com.fast.easy.instant.rapid.quickloan.miniloan.cash.loan.coach",
        "com.ptechmini.instantcredit",
        "com.warehouse.scan_collect",
        "com.hayat.islamicloanmaster",
        "com.pk.finbook",
        "com.app.yelonow",
        "com.ywgspm.zhcohpf",
        "com.pakistan.instantloan.kolibre",
        "com.din.karaz.loan.cash.qarza.credit.jazz.paisa.barwaqt.easy",
        "com.from.outside",
        # --- New additions for Nigeria delisted ---
        "com.creditbank.fastcash.onlineinstant.personalloan.access.moneybox.financeloan",
        "com.libertyloans.loans",
        "com.ease.naira.cash.loan.app.ngn",
        "com.nigeria.aimloan",
        "com.dnf.naira",
        "com.princepsfinance.creditwallet",
        "com.cashpro.kash.lending.loan"
    },
    ("Kenya", "approved"): {
        "com.kenya.credit.app.loan.cash.money.pesa",
        "com.kopakash",
        "com.zenkafinance.microloans",
        "com.koro.microloans",
        "com.linkpesa.cashltd",
        "bank.com.bank",
        "ke.co.kingdombankltd.mobile",
        "com.okoleainternational.okoleamobile",
        "p.rocketpesa",
        "com.credit.truepesa.loan.kenya",
        "org.mifos.maralal",
        "com.inventureaccess.safarirahisi",
        "com.flash.flashcredit",
        "credit.gason.shcake.niadayw",
        "kenya.easybuy.client",
        "com.kashbean",
        "com.txd.overseasfinance",
        "com.poacash"
    }
}

# Build a mapping: package -> (Country, Classification)
package_to_group = {}
for (country, classification), pkg_set in groups.items():
    for pkg in pkg_set:
        # If a package appears in more than one group, keep the first encountered.
        if pkg not in package_to_group:
            package_to_group[pkg] = (country, classification)

# Dictionary to store first occurrence of each package with its sha256
found_rows = {}

input_file = "androzoosha256_clean.csv"
chunksize = 100000  # Adjust based on available memory

# Process the CSV file in chunks.
for chunk in pd.read_csv(input_file, chunksize=chunksize):
    # Filter rows whose pkg_name is in our mapping.
    mask = chunk["pkg_name"].isin(package_to_group.keys())
    filtered = chunk[mask]
    
    for _, row in filtered.iterrows():
        pkg = row["pkg_name"]
        # Only record the first occurrence for each package
        if pkg not in found_rows:
            country, classification = package_to_group[pkg]
            found_rows[pkg] = {
                "Country": country,
                "Classification": classification,
                "Package": pkg,
                "sha256": row["sha256"]
            }

# Convert the results to a DataFrame
result_df = pd.DataFrame(list(found_rows.values()))

# Save to CSV with columns: Country, Classification, Package, sha256
output_csv = "found_packages.csv"
result_df.to_csv(output_csv, index=False)
print(f"Results saved to '{output_csv}'.")

# Print summary counts per group to console
group_counts = {}
for row in found_rows.values():
    key = (row["Country"], row["Classification"])
    group_counts[key] = group_counts.get(key, 0) + 1

print("\nCounts per group:")
for (country, classification), count in group_counts.items():
    print(f"{country} {classification}: {count}")

