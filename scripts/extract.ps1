$Configuration = $args[0]

if (($Configuration -cne "Release") -and ($Configuration -cne "Debug")) {
    echo "Usage: extract.ps1 Release|Debug"
    exit 1
}

robocopy C:/ipaSim/build/ipasim-x86-$Configuration/bin C:/ipaSim/src/cmake/ipasim-x86-$Configuration/bin * /MIR /NP /NFL /NDL
robocopy C:/ipaSim/build/winobjc-x86-$Configuration/bin C:/ipaSim/src/cmake/winobjc-x86-$Configuration/bin * /MIR /NP /NFL /NDL
robocopy C:/ipaSim/build/lief-x86-$Configuration/include C:/ipaSim/src/cmake/lief-x86-$Configuration/include * /MIR /NP /NFL /NDL
robocopy C:/ipaSim/build/ipasim-x86-$Configuration/gen C:/ipaSim/src/src/IpaSimulator/IpaSimApp/gen * /MIR /NP /NFL /NDL
robocopy C:/ipaSim/src/deps/WinObjC/Frameworks/UIKit.Xaml/prebuilt/$Configuration C:/ipaSim/src/src/IpaSimulator/IpaSimApp/UIKit.Xaml *.xbf /MIR /NP /NFL /NDL
robocopy C:/ipaSim/src/deps/WinObjC/Frameworks/Social.Xaml/prebuilt/$Configuration C:/ipaSim/src/src/IpaSimulator/IpaSimApp/Social.Xaml *.xbf /MIR /NP /NFL /NDL
