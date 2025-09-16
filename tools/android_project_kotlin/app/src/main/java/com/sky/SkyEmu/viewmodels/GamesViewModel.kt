
package com.sky.SkyEmu.viewmodels

import android.net.Uri
import androidx.documentfile.provider.DocumentFile
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.preference.PreferenceManager
import com.sky.SkyEmu.SkyEmuApplication
import com.sky.SkyEmu.models.Game
import com.sky.SkyEmu.utils.GameUtils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import java.util.Locale

class GamesViewModel : ViewModel() {
    val games get() = _games.asStateFlow()
    private val _games = MutableStateFlow(emptyList<Game>())

    val searchedGames get() = _searchedGames.asStateFlow()
    private val _searchedGames = MutableStateFlow(emptyList<Game>())

    val isReloading get() = _isReloading.asStateFlow()
    private val _isReloading = MutableStateFlow(false)

    val shouldSwapData get() = _shouldSwapData.asStateFlow()
    private val _shouldSwapData = MutableStateFlow(false)

    val shouldScrollToTop get() = _shouldScrollToTop.asStateFlow()
    private val _shouldScrollToTop = MutableStateFlow(false)

    val searchFocused get() = _searchFocused.asStateFlow()
    private val _searchFocused = MutableStateFlow(false)

    init {
        // Retrieve list of games
        setGames(GameUtils.getGames())
        reloadGames(false)
    }

    fun setGames(games: List<Game>) {
        _games.value = games
    }

    fun setSearchedGames(games: List<Game>) {
        _searchedGames.value = games
    }

    fun setShouldSwapData(shouldSwap: Boolean) {
        _shouldSwapData.value = shouldSwap
    }

    fun setShouldScrollToTop(shouldScroll: Boolean) {
        _shouldScrollToTop.value = shouldScroll
    }

    fun setSearchFocused(searchFocused: Boolean) {
        _searchFocused.value = searchFocused
    }

    fun reloadGames(directoryChanged: Boolean) {
        if (isReloading.value) {
            return
        }
        _isReloading.value = true

        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                setGames(GameUtils.getGames())
                _isReloading.value = false

                /*if (directoryChanged) {
                    setShouldSwapData(true)
                }*/
            }
        }
    }
}
