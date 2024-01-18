import { StyleSheet  } from 'react-native'

const contentStyles = StyleSheet.create({
  image: {
    width: '100%',
    height: 200
  },
  title: {
    color: 'white', 
    fontSize: 32, 
    fontWeight: 'bold', 
    paddingTop: 16, 
    paddingLeft: 16, 
    paddingRight: 16
  },
  explanation: { 
    color: 'white', padding: 16
  }
})

const loadingStyles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center'
  },
  title: {
    color: 'white',
    fontSize: 40,
    fontWeight: 'bold',
    paddingBottom: 20
  }
})

const errorStyles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center'
  },
  message: {
    padding: 16,
    marginLeft: 16,
    marginRight: 16,
    borderRadius: 8,
    overflow: 'hidden',
    color: 'white',
    backgroundColor: '#EA6A61'
  }
})

module.exports = {
  content: contentStyles,
  loading: loadingStyles,
  error: errorStyles
}