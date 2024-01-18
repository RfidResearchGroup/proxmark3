/**
  A basic React Native app where you
  can find how to perform a networking
  request, update the app state and
  layout some basic components.
*/

import Styles from './styles.jsx'
import Constants from './constants.jsx'
import React from 'react'
import { 
  AppRegistry, 
  ActivityIndicator,
  ScrollView,
  Image,
  Text,
  View
} from 'react-native'

export default class APOD extends React.Component {

  constructor(props) {
    super(props)
    this.state = { isLoading: true }
  }

  componentDidMount() {
    return fetch(
      'https://api.nasa.gov/planetary/apod?api_key=' + Constants.apiKey
    ).then(response => response.json()
    ).then(responseJson => {
      this.setState({
        isLoading: false,
        dataSource: responseJson
      }, () => {})
    }).catch((error) => {
      console.log(error)
    })
  }

  render() {
    // Loading state
    if (this.state.isLoading) {
      return (
        <View style={ Styles.loading.container }>
          <Text style={ Styles.loading.title }>
            APOD
          </Text>
          <ActivityIndicator size='small'/>
        </View>
      );
    }
    
    // Error state
    if (this.state.dataSource.error) {
      return (
        <View style={ Styles.error.container }>
          <Text style={ Styles.error.message }>
            { this.state.dataSource.error.message }
          </Text>
        </View>
      )
    }

    // Fetched content state
    return (
      <ScrollView>
      	<Image
      	  source={{ uri: this.state.dataSource.url }}
      	  style={ Styles.content.image }
      	/>
      	<Text style={ Styles.content.title }>
      	  { this.state.dataSource.title }
      	</Text>
      	<Text style={ Styles.content.explanation }>
      	  { this.state.dataSource.explanation }
      	</Text>
      </ScrollView>
    )
  }
}

//  In order to render the component
//  you need to register it with the
//  same name as your app
AppRegistry.registerComponent(
  'Astronomy Picture', () => APOD
)